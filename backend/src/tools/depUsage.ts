import { promises as fs } from "fs";
import path from "path";
import { Finding, Severity } from "../schema/finding";
import { isDependency } from "../orchestrator/reachability";
import { isNonProductionPath } from "../orchestrator/filterFindings";

/**
 * Dependency usage: where does the app actually load each vulnerable package?
 *
 * This is the deterministic half of dependency reachability. For every dependency finding it
 * looks for imports of the package itself, or of the direct dependency that pulls it in
 * (metadata.pulledInBy), in the repo's own source files and package.json scripts. The result
 * goes into metadata.usage, with a few lines of context around each import, so the AI (built-in
 * triage or the coding agent) can judge whether the vulnerable code is reachable from it.
 *
 * Without AI, a production package that is never imported, referenced or run is lowered one
 * level: it ships, but nothing in the app loads it. It is never removed.
 */

export type UsageStatus =
  /** The package, or the direct dependency that pulls it in, is imported by app code. */
  | "imported"
  /** Not imported, but named in a string or a package.json script (loaded dynamically or run as a CLI). */
  | "referenced"
  /** Nothing in the app loads it. */
  | "not_found"
  /** Not found, but it's a transitive package whose path from the app's direct dependencies isn't known. */
  | "unknown"
  /** Ecosystem this check doesn't parse (e.g. Java, Go): treated as unknown. */
  | "unsupported";

export interface UsageSite {
  /** The package actually imported here: the vulnerable one, or the direct dependency pulling it in. */
  pkg: string;
  file: string;
  line: number;
  kind: "import" | "reference" | "script";
  /** A few lines around the site, so the reviewer can see how it's used. Masked later with the rest of metadata. */
  context?: string;
}

export interface DependencyUsage {
  status: UsageStatus;
  /** Packages searched for: the vulnerable package plus the direct dependencies that pull it in. */
  searched: string[];
  sites: UsageSite[];
  /** Total sites found, which may exceed sites.length (capped for size). */
  totalSites: number;
}

const SOURCE_EXT = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".py", ".html", ".ejs", ".hbs"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "out", "coverage", "vendor", ".next", ".nuxt", "__pycache__", ".venv", "venv", "bower_components"]);
const MAX_FILES = 4000;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_SITES = 4;
const CONTEXT_LINES = 3;
const SUPPORTED_ECOSYSTEMS = new Set(["npm", "pypi"]);
const SEVERITY_DOWN: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "low" };

interface SourceFile {
  rel: string;
  lines: string[];
  python: boolean;
}

async function collectSources(repoDir: string): Promise<SourceFile[]> {
  const out: SourceFile[] = [];
  const walk = async (dir: string): Promise<void> => {
    if (out.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES) return;
      const abs = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) await walk(abs);
        continue;
      }
      const ext = path.extname(e.name).toLowerCase();
      if (!SOURCE_EXT.has(ext)) continue;
      // Minified bundles are third-party code, not the app's own usage.
      if (/\.min\.(js|mjs|cjs)$/i.test(e.name)) continue;
      const rel = path.relative(repoDir, abs).split(path.sep).join("/");
      // Usage only in tests, examples or docs doesn't ship, so it doesn't make a package reachable.
      if (isNonProductionPath(rel)) continue;
      try {
        const stat = await fs.stat(abs);
        if (stat.size > MAX_FILE_BYTES) continue;
        const text = await fs.readFile(abs, "utf8");
        out.push({
          rel,
          lines: text.split("\n"),
          python: ext === ".py",
        });
      } catch {
        // Unreadable file: skip.
      }
    }
  };
  await walk(repoDir);
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Import of `pkg` or a subpath of it (`pkg/sub`), in require/import/dynamic-import/export-from form. */
function jsImportRe(pkg: string): RegExp {
  const name = escapeRe(pkg);
  return new RegExp(
    `(?:\\brequire\\s*\\(\\s*|\\bimport\\s*\\(\\s*|\\bfrom\\s+|\\bimport\\s+)(['"\`])${name}(?:/[^'"\`]*)?\\1`
  );
}

/** Python: `import pkg`, `import pkg.sub`, `from pkg import`, with dashes normalised to underscores. */
function pyImportRe(pkg: string): RegExp {
  const name = escapeRe(pkg.toLowerCase().replace(/-/g, "_"));
  return new RegExp(`^\\s*(?:from\\s+${name}(?:\\.[\\w.]+)?\\s+import\\b|import\\s+(?:[\\w.]+\\s*,\\s*)*${name}(?:\\.|\\s|,|$))`, "i");
}

/**
 * The package name as a whole quoted string, e.g. app.set("view engine", "ejs"). Names shorter
 * than 3 characters (npm has "i", "q", "co") would match ordinary strings, so they are skipped.
 */
function stringRefRe(pkg: string): RegExp | null {
  if (pkg.replace(/^@[^/]+\//, "").length < 3) return null;
  return new RegExp(`(['"\`])${escapeRe(pkg)}\\1`);
}

function contextAround(lines: string[], index: number): string {
  const start = Math.max(0, index - CONTEXT_LINES);
  const end = Math.min(lines.length, index + CONTEXT_LINES + 1);
  return lines
    .slice(start, end)
    .map((t, i) => `${start + i + 1}: ${t.length > 200 ? `${t.slice(0, 200)}…` : t}`)
    .join("\n");
}

async function readScripts(repoDir: string): Promise<{ file: string; scripts: Record<string, string> }[]> {
  const out: { file: string; scripts: Record<string, string> }[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 4) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.isSymbolicLink()) await walk(abs, depth + 1);
      else if (e.isFile() && e.name === "package.json") {
        try {
          const pkg = JSON.parse(await fs.readFile(abs, "utf8"));
          if (pkg && typeof pkg.scripts === "object" && pkg.scripts) {
            out.push({ file: path.relative(repoDir, abs).split(path.sep).join("/"), scripts: pkg.scripts });
          }
        } catch {
          // Not valid JSON: skip.
        }
      }
    }
  };
  await walk(repoDir, 0);
  return out;
}

/** Search the given sources for each candidate package; pure, so it is testable without a repo. */
export function findUsage(
  candidates: string[],
  sources: SourceFile[],
  scripts: { file: string; scripts: Record<string, string> }[],
  python: boolean
): DependencyUsage {
  const imports: UsageSite[] = [];
  const references: UsageSite[] = [];
  for (const pkg of candidates) {
    const importRe = python ? pyImportRe(pkg) : jsImportRe(pkg);
    const refRe = stringRefRe(pkg);
    for (const src of sources) {
      if (src.python !== python) continue;
      src.lines.forEach((line, i) => {
        if (importRe.test(line)) {
          imports.push({ pkg, file: src.rel, line: i + 1, kind: "import", context: contextAround(src.lines, i) });
        } else if (!python && refRe?.test(line)) {
          references.push({ pkg, file: src.rel, line: i + 1, kind: "reference", context: contextAround(src.lines, i) });
        }
      });
    }
    if (!python && pkg.length >= 3) {
      const word = new RegExp(`(^|[\\s;&|(/])${escapeRe(pkg)}(?=$|[\\s;&|)])`);
      for (const { file, scripts: s } of scripts) {
        for (const [name, cmd] of Object.entries(s)) {
          if (typeof cmd === "string" && word.test(cmd)) {
            references.push({ pkg, file, line: 0, kind: "script", context: `"${name}": ${JSON.stringify(cmd)}` });
          }
        }
      }
    }
  }
  const sites = imports.length ? imports : references;
  return {
    status: imports.length ? "imported" : references.length ? "referenced" : "not_found",
    searched: candidates,
    sites: sites.slice(0, MAX_SITES),
    totalSites: sites.length,
  };
}

/**
 * npm dependency graph from a package-lock.json / npm-shrinkwrap.json: who depends on whom,
 * and which packages the manifest lists directly.
 */
export interface LockGraph {
  direct: Set<string>;
  dependents: Map<string, Set<string>>;
}

const LOCK_NAMES = ["package-lock.json", "npm-shrinkwrap.json"];

function nameFromLockKey(key: string): string {
  const i = key.lastIndexOf("node_modules/");
  return i === -1 ? key : key.slice(i + "node_modules/".length);
}

export function buildLockGraph(lock: unknown, manifest: unknown): LockGraph {
  const direct = new Set<string>();
  const dependents = new Map<string, Set<string>>();
  const add = (child: string, parent: string) => {
    if (child === parent) return;
    if (!dependents.has(child)) dependents.set(child, new Set());
    dependents.get(child)!.add(parent);
  };
  const depNames = (o: Record<string, unknown> | undefined) =>
    Object.keys({ ...(o?.dependencies as object), ...(o?.optionalDependencies as object), ...(o?.peerDependencies as object) });
  const m = (manifest ?? {}) as Record<string, unknown>;
  for (const n of [...depNames(m), ...Object.keys((m.devDependencies as object) ?? {})]) direct.add(n);
  const l = (lock ?? {}) as Record<string, unknown>;
  const packages = l.packages as Record<string, Record<string, unknown>> | undefined;
  if (packages && typeof packages === "object") {
    // lockfileVersion 2/3: flat "node_modules/a/node_modules/b" entries.
    for (const [key, entry] of Object.entries(packages)) {
      if (key === "") continue;
      const parent = nameFromLockKey(key);
      for (const child of depNames(entry)) add(child, parent);
    }
  } else if (l.dependencies && typeof l.dependencies === "object") {
    // lockfileVersion 1: nested "dependencies" with "requires".
    const walk = (deps: Record<string, Record<string, unknown>>) => {
      for (const [name, entry] of Object.entries(deps)) {
        for (const child of Object.keys((entry.requires as object) ?? {})) add(child, name);
        if (entry.dependencies && typeof entry.dependencies === "object") walk(entry.dependencies as Record<string, Record<string, unknown>>);
      }
    };
    walk(l.dependencies as Record<string, Record<string, unknown>>);
  }
  return { direct, dependents };
}

/** The app's direct dependencies that (transitively) bring in `pkg`; [pkg] itself if it is direct. */
export function directAncestors(graph: LockGraph, pkg: string): string[] {
  const out = new Set<string>();
  if (graph.direct.has(pkg)) out.add(pkg);
  const seen = new Set<string>([pkg]);
  const queue = [...(graph.dependents.get(pkg) ?? [])];
  while (queue.length) {
    const p = queue.shift()!;
    if (seen.has(p)) continue;
    seen.add(p);
    if (graph.direct.has(p)) out.add(p);
    for (const q of graph.dependents.get(p) ?? []) queue.push(q);
  }
  return [...out].sort();
}

async function loadLockGraph(repoDir: string, manifestRel: string): Promise<LockGraph | null> {
  const dir = path.resolve(repoDir, path.posix.dirname(manifestRel));
  if (dir !== path.resolve(repoDir) && !dir.startsWith(path.resolve(repoDir) + path.sep)) return null;
  for (const name of LOCK_NAMES) {
    try {
      const [lock, manifest] = await Promise.all([
        fs.readFile(path.join(dir, name), "utf8").then(JSON.parse),
        fs.readFile(path.join(dir, "package.json"), "utf8").then(JSON.parse).catch(() => ({})),
      ]);
      return buildLockGraph(lock, manifest);
    } catch {
      // Try the next lockfile name.
    }
  }
  return null;
}

interface Candidates {
  pkgs: string[];
  python: boolean;
  /** True when every direct dependency that brings the package in is known, so "not found" is conclusive. */
  complete: boolean;
}

async function candidatesFor(f: Finding, repoDir: string, graphs: Map<string, Promise<LockGraph | null>>): Promise<Candidates | null> {
  const pkg = typeof f.metadata.package === "string" ? f.metadata.package : null;
  if (!pkg) return null;
  const ecosystem = typeof f.metadata.ecosystem === "string" ? f.metadata.ecosystem.toLowerCase() : "npm";
  if (!SUPPORTED_ECOSYSTEMS.has(ecosystem)) return null;
  const pulledInBy = Array.isArray(f.metadata.pulledInBy) ? (f.metadata.pulledInBy as unknown[]).filter((p): p is string => typeof p === "string") : [];
  const pkgs = new Set([pkg, ...pulledInBy]);
  let complete = f.metadata.direct === true;
  // npm audit's "pulled in by" only follows chains of vulnerable packages; the lockfile has the full graph.
  if (ecosystem === "npm" && f.location.file && !f.metadata.lockfileGenerated) {
    const key = f.location.file;
    if (!graphs.has(key)) graphs.set(key, loadLockGraph(repoDir, key));
    const graph = await graphs.get(key)!;
    if (graph) {
      const ancestors = directAncestors(graph, pkg);
      ancestors.forEach((a) => pkgs.add(a));
      complete = complete || ancestors.length > 0;
    }
  }
  return { pkgs: [...pkgs], python: ecosystem === "pypi", complete };
}

function describe(u: DependencyUsage, pkg: string): string {
  const via = (s: UsageSite) => (s.pkg === pkg ? "" : ` (via ${s.pkg}, which pulls it in)`);
  const where = (s: UsageSite) => (s.line ? `${s.file}:${s.line}` : `${s.file} scripts`);
  switch (u.status) {
    case "imported":
      return ` Imported in ${u.sites.map((s) => `${where(s)}${via(s)}`).join(", ")}${u.totalSites > u.sites.length ? ` and ${u.totalSites - u.sites.length} more` : ""}.`;
    case "referenced":
      return ` Not imported directly, but referenced in ${u.sites.map(where).join(", ")}, so it may be loaded dynamically or run as a command.`;
    case "not_found":
      return ` No import of ${u.searched.length > 4 ? `${u.searched.slice(0, 4).join(", ")} or ${u.searched.length - 4} other packages that pull it in` : u.searched.join(" or ")} was found in the app's code or package.json scripts, so it is installed but not loaded by the app.`;
    default:
      return "";
  }
}

/**
 * Attach metadata.usage to every dependency finding and, for production packages nothing
 * loads, lower the severity one level (never for CISA KEV entries; never removed).
 */
export async function enrichWithUsage(repoDir: string, findings: Finding[]): Promise<{ notFound: number; imported: number; lowered: number }> {
  const deps = findings.filter(isDependency);
  if (deps.length === 0) return { notFound: 0, imported: 0, lowered: 0 };
  const [sources, scripts] = await Promise.all([collectSources(repoDir), readScripts(repoDir)]);
  const graphs = new Map<string, Promise<LockGraph | null>>();
  let notFound = 0;
  let imported = 0;
  let lowered = 0;
  for (const f of deps) {
    const c = await candidatesFor(f, repoDir, graphs);
    const pkg = String(f.metadata.package ?? "");
    let usage: DependencyUsage = c
      ? findUsage(c.pkgs, sources, scripts, c.python)
      : { status: "unsupported", searched: pkg ? [pkg] : [], sites: [], totalSites: 0 };
    // Without the full path from the app's direct dependencies, "not found" isn't conclusive.
    if (c && usage.status === "not_found" && !c.complete) usage = { ...usage, status: "unknown" };
    f.metadata = { ...f.metadata, usage };
    f.tool_message += describe(usage, pkg);
    if (usage.status === "imported") imported++;
    if (usage.status === "not_found") {
      notFound++;
      if (!f.metadata.devOnly && !f.metadata.kev && f.severity !== "low") {
        const from = f.severity;
        lowered++;
        f.severity = SEVERITY_DOWN[from];
        f.metadata = { ...f.metadata, loweredByUsage: { from, to: f.severity } };
        f.tool_message += ` Lowered from ${from} to ${f.severity} for that reason; still upgrade it.`;
      }
    }
  }
  return { notFound, imported, lowered };
}
