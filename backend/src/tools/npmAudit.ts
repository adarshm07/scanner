import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { Category, Finding, makeFindingId, Severity } from "../schema/finding";
import { describeFailure, runCommand } from "./util";
import { ToolRun } from "./types";

/**
 * npm audit — dependency vulnerabilities (repo mode). Parses `npm audit --json`
 * (npm v7+ schema). Adapter isolates all npm-specific parsing.
 */

interface NpmAuditVia {
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string[];
  source?: number;
}

interface NpmAuditAdvisory {
  name: string;
  severity: string; // info | low | moderate | high | critical
  via: (string | NpmAuditVia)[];
  range?: string;
  nodes?: string[];
  isDirect?: boolean;
  fixAvailable?: boolean | { name: string; version: string };
}

/** `packages` section of a v2/v3 package-lock.json: install path -> flags. */
export type LockPackages = Record<string, { dev?: boolean; devOptional?: boolean; optional?: boolean; inBundle?: boolean }>;

/** A bundled package (inside another package's tarball) inherits its bundler's dev flag. */
function lockEntryIsDev(lock: LockPackages, node: string): boolean {
  const entry = lock[node];
  if (!entry) return false;
  if (entry.dev === true) return true;
  if (!entry.inBundle) return false;
  const parent = node.slice(0, node.lastIndexOf("/node_modules/"));
  return parent.length > 0 && parent !== node && lockEntryIsDev(lock, parent);
}

/**
 * True when every installed copy of the package is a dev dependency (npm marks these
 * `dev: true` in the lockfile). Such code runs on developer and CI machines, not in
 * production, so an advisory against it is not exploitable through the shipped app.
 */
export function isDevOnly(nodes: string[] | undefined, lock: LockPackages | undefined): boolean {
  if (!lock || !nodes?.length) return false;
  return nodes.every((n) => lockEntryIsDev(lock, n));
}

interface NpmAuditRaw {
  vulnerabilities?: Record<string, NpmAuditAdvisory>;
  error?: { code?: string; summary?: string };
}

function mapSeverity(npm: string): Severity {
  switch (npm) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    default:
      return "low";
  }
}

const NPM_RANK: Record<string, number> = { critical: 4, high: 3, moderate: 2, low: 1, info: 0 };
const GHSA_IN_URL = /GHSA-[\w-]+/i;

/**
 * One finding per package that has its own advisories.
 *
 * npm audit also lists every package that is "vulnerable" only because something below it
 * is (its `via` holds package names, not advisories). Those entries repeat the same issue
 * up the tree, so they are folded into the advisory they lead to as "pulled in by", which
 * is also what tells the reader which direct dependency to upgrade.
 */
export function npmAuditAdapter(
  raw: NpmAuditRaw,
  manifest = "package.json",
  category: Category = "backend",
  lock?: LockPackages
): Finding[] {
  const vulns = raw.vulnerabilities ?? {};
  const advisoriesOf = (adv: NpmAuditAdvisory) => {
    const seen = new Set<string>();
    return adv.via
      .filter((v): v is NpmAuditVia => typeof v === "object")
      .filter((v) => {
        const key = v.url ?? v.title ?? String(v.source);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .sort((a, b) => (NPM_RANK[b.severity ?? ""] ?? 0) - (NPM_RANK[a.severity ?? ""] ?? 0));
  };

  // parent -> children it is vulnerable through; inverted to walk up to direct dependencies.
  const parentsOf = new Map<string, string[]>();
  for (const [pkg, adv] of Object.entries(vulns)) {
    for (const v of adv.via) {
      if (typeof v !== "string") continue;
      parentsOf.set(v, [...(parentsOf.get(v) ?? []), pkg]);
    }
  }
  const directAncestors = (pkg: string): string[] => {
    const out = new Set<string>();
    const seen = new Set<string>([pkg]);
    const queue = [...(parentsOf.get(pkg) ?? [])];
    while (queue.length) {
      const p = queue.shift()!;
      if (seen.has(p)) continue;
      seen.add(p);
      if (vulns[p]?.isDirect) out.add(p);
      queue.push(...(parentsOf.get(p) ?? []));
    }
    return [...out].sort();
  };

  const findings: Finding[] = [];
  for (const [pkg, adv] of Object.entries(vulns)) {
    const advisories = advisoriesOf(adv);
    // Propagation-only entry: reported through the advisory it leads to.
    if (advisories.length === 0 && adv.via.length > 0) continue;
    const top = advisories[0];
    const ruleId = top?.url ? top.url : `npm-advisory-${pkg}`;
    const devOnly = isDevOnly(adv.nodes, lock);
    const toolSeverity = mapSeverity(adv.severity);
    const pulledInBy = adv.isDirect ? [] : directAncestors(pkg);
    const more = advisories.length > 1 ? ` (+${advisories.length - 1} more ${advisories.length === 2 ? "advisory" : "advisories"})` : "";
    const list = advisories
      .slice(0, 5)
      .map((a) => `${a.title ?? "advisory"}${a.severity ? ` [${a.severity}]` : ""}`)
      .join("; ");
    findings.push({
      skill: `npm-audit-${pkg}`,
      category,
      finding_id: makeFindingId({ file: manifest, rule_id: `${pkg}:${adv.range ?? ""}` }),
      rule_id: ruleId,
      // Dev-only packages never ship, so they are capped at low (still listed, never gate a PR).
      severity: devOnly ? "low" : toolSeverity,
      confidence: "high",
      title: `${devOnly ? "Dev dependency " : ""}${pkg}: ${top?.title ?? "known vulnerability"}${more}`,
      location: { file: manifest },
      raw_snippet: null,
      tool_message:
        `${pkg}${adv.range ? ` ${adv.range}` : ""} is affected by: ${list || "a known vulnerability"}${advisories.length > 5 ? `; and ${advisories.length - 5} more` : ""}.` +
        (pulledInBy.length ? ` Not a direct dependency: pulled in by ${pulledInBy.join(", ")}.` : "") +
        (devOnly
          ? ` ${pkg} is only installed as a dev dependency (build, test or lint tooling), so it does not ship with the app; npm rates it ${adv.severity}.`
          : ""),
      metadata: {
        cwe: top?.cwe?.[0],
        owasp: "A06:2021-Vulnerable and Outdated Components",
        package: pkg,
        range: adv.range,
        devOnly,
        direct: !!adv.isDirect,
        pulledInBy,
        toolSeverity,
        fixAvailable: adv.fixAvailable,
        advisoryUrl: top?.url,
        advisoryIds: advisories
          .map((a) => a.url?.match(GHSA_IN_URL)?.[0])
          .filter((id): id is string => !!id),
      },
    });
  }
  return findings;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "vendor"]);
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"];
const AUDIT_TIMEOUT_MS = 120000;
const FRONTEND_DIRS = /(^|\/)(frontend|client|web|ui|app|www)(\/|$)/i;
const FRONTEND_DEPS = ["react", "vue", "svelte", "@angular/core", "next", "nuxt", "vite"];

async function categoryForManifest(dir: string, rel: string): Promise<Category> {
  if (FRONTEND_DIRS.test(rel)) return "frontend";
  try {
    const pkg = JSON.parse(await fs.readFile(path.join(dir, "package.json"), "utf8"));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (FRONTEND_DEPS.some((d) => d in deps)) return "frontend";
  } catch {
    // Unreadable manifest: default to backend.
  }
  return "backend";
}

interface ManifestDir {
  dir: string;
  hasLockfile: boolean;
  /** package.json declares npm workspaces (members share this directory's lockfile). */
  isWorkspaceRoot: boolean;
}

async function findManifestDirs(root: string): Promise<ManifestDir[]> {
  const out: ManifestDir[] = [];
  const walk = async (dir: string) => {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const files = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
    // yarn/pnpm projects are scanned by OSV-Scanner from their own lockfile; resolving an
    // npm lockfile for them would report different versions (and duplicates).
    if (files.has("package.json") && !files.has("yarn.lock") && !files.has("pnpm-lock.yaml")) {
      let isWorkspaceRoot = false;
      try {
        isWorkspaceRoot = !!JSON.parse(await fs.readFile(path.join(dir, "package.json"), "utf8")).workspaces;
      } catch {
        /* unreadable manifest: treat as a plain package */
      }
      out.push({ dir, hasLockfile: LOCKFILES.some((f) => files.has(f)), isWorkspaceRoot });
    }
    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) await walk(path.join(dir, e.name));
    }
  };
  await walk(root);
  return out;
}

const REGISTRY = "--registry=https://registry.npmjs.org/";
const LOCK_TIMEOUT_MS = 180000;

/** First meaningful "npm error" line (npm ends stderr with a pointer to its log file). */
function npmErrorLine(res: { stderr: string }): string | null {
  const line = res.stderr
    .split("\n")
    .map((l) => l.replace(/^npm (error|ERR!)\s*/, "").trim())
    .find((l, i, all) => l && !/complete log of this run/i.test(l) && /^npm (error|ERR!)/.test(res.stderr.split("\n")[i] ?? ""));
  return line ? line.slice(0, 200) : null;
}

type AuditOutcome = { raw: NpmAuditRaw; lock?: LockPackages } | { error: string };

async function readLock(dir: string): Promise<LockPackages | undefined> {
  for (const f of LOCKFILES) {
    try {
      const parsed = JSON.parse(await fs.readFile(path.join(dir, f), "utf8"));
      // v1 lockfiles (npm 6) have no `packages` section; dev detection is skipped for them.
      if (parsed && typeof parsed.packages === "object") return parsed.packages as LockPackages;
      return undefined;
    } catch {
      /* try the next lockfile name */
    }
  }
  return undefined;
}

async function audit(cwd: string): Promise<AuditOutcome> {
  // Pin the registry so a repo's own .npmrc can't point npm at another host.
  const res = await runCommand("npm", ["audit", "--json", REGISTRY], { cwd, timeoutMs: AUDIT_TIMEOUT_MS });
  try {
    if (res.spawnError || res.timedOut) throw new Error();
    const parsed = JSON.parse(res.stdout) as NpmAuditRaw;
    if (parsed.error) return { error: parsed.error.code ?? parsed.error.summary ?? "npm audit error" };
    return { raw: parsed, lock: await readLock(cwd) };
  } catch {
    return { error: describeFailure(res, AUDIT_TIMEOUT_MS) };
  }
}

/**
 * Resolve a lockfile for a manifest that has none, in a throwaway directory so the scanned
 * checkout is never modified. Only package.json files are copied (plus workspace members'),
 * install scripts never run, and the registry is pinned.
 */
async function auditWithGeneratedLockfile(dir: string, members: string[]): Promise<AuditOutcome> {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-lock-"));
  try {
    await fs.copyFile(path.join(dir, "package.json"), path.join(tmp, "package.json"));
    for (const member of members) {
      const rel = path.relative(dir, member);
      await fs.mkdir(path.join(tmp, rel), { recursive: true });
      await fs.copyFile(path.join(member, "package.json"), path.join(tmp, rel, "package.json"));
    }
    const base = [
      "install", "--package-lock-only", "--package-lock=true", "--ignore-scripts",
      "--no-audit", "--no-fund", REGISTRY,
    ];
    let res = await runCommand("npm", base, { cwd: tmp, timeoutMs: LOCK_TIMEOUT_MS });
    // Peer-dependency conflicts (ERESOLVE, and some npm resolver crashes on them) are common in
    // app repos; retry resolving them the way npm 6 did.
    if (!res.spawnError && !res.timedOut && res.code !== 0) {
      res = await runCommand("npm", [...base, "--legacy-peer-deps"], { cwd: tmp, timeoutMs: LOCK_TIMEOUT_MS });
    }
    if (res.spawnError || res.timedOut || res.code !== 0) {
      return { error: `could not resolve dependencies without a lockfile (${npmErrorLine(res) ?? describeFailure(res, LOCK_TIMEOUT_MS)})` };
    }
    return await audit(tmp);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

export async function runNpmAudit(repoDir: string): Promise<ToolRun> {
  const manifests = await findManifestDirs(repoDir);
  if (manifests.length === 0) return { findings: [], ran: true };
  const isUnder = (dir: string, parent: string) => parent !== dir && dir.startsWith(parent + path.sep);
  // Workspace members share an ancestor's lockfile (real or generated); audit them through it.
  const coveredByAncestor = (dir: string) =>
    manifests.some((m) => (m.hasLockfile || m.isWorkspaceRoot) && isUnder(dir, m.dir));

  const findings: Finding[] = [];
  const errors: string[] = [];
  for (const { dir, hasLockfile, isWorkspaceRoot } of manifests) {
    const rel = path.relative(repoDir, dir).split(path.sep).join("/") || ".";
    if (!hasLockfile && coveredByAncestor(dir)) continue;

    const members = isWorkspaceRoot ? manifests.filter((m) => isUnder(m.dir, dir)).map((m) => m.dir) : [];
    const outcome = hasLockfile ? await audit(dir) : await auditWithGeneratedLockfile(dir, members);
    if ("error" in outcome) {
      errors.push(`${rel}: ${outcome.error}`);
      continue;
    }
    const category = await categoryForManifest(dir, rel);
    const manifest = path.posix.join(rel, "package.json");
    for (const f of npmAuditAdapter(outcome.raw, manifest, category, outcome.lock)) {
      if (!hasLockfile) {
        f.tool_message += ` Versions were resolved by the scanner from ${manifest} because the repo has no lockfile, so the versions you actually install may differ.`;
        f.metadata = { ...f.metadata, lockfileGenerated: true };
      }
      findings.push(f);
    }
  }
  return { findings, ran: errors.length === 0, error: errors.join("; ") || undefined };
}
