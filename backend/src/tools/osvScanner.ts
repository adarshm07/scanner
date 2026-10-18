import { promises as fs } from "fs";
import path from "path";
import { Finding, makeFindingId, Severity } from "../schema/finding";
import { checkTool, describeFailure, runCommand } from "./util";
import { ToolRun } from "./types";

/**
 * OSV-Scanner — dependency vulnerabilities for non-JavaScript ecosystems (Python, Java,
 * Rust, Go, Ruby, PHP, .NET, Dart, ...), checked against the OSV.dev database.
 * JavaScript stays with npm audit (see npmAudit.ts), so npm lockfile results are dropped
 * here to avoid reporting the same advisory twice.
 */

const SKIP_DIRS = new Set([
  "node_modules", ".git", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__", ".gradle", ".idea",
]);

/** Files OSV-Scanner can read, by ecosystem. */
const LOCKFILES = new Map<string, string>([
  ["requirements.txt", "Python"],
  ["Pipfile.lock", "Python"],
  ["poetry.lock", "Python"],
  ["uv.lock", "Python"],
  ["pdm.lock", "Python"],
  ["pom.xml", "Java (Maven)"],
  ["gradle.lockfile", "Java (Gradle)"],
  ["buildscript-gradle.lockfile", "Java (Gradle)"],
  ["Cargo.lock", "Rust"],
  ["go.mod", "Go"],
  ["Gemfile.lock", "Ruby"],
  ["composer.lock", "PHP"],
  ["packages.lock.json", ".NET"],
  ["pubspec.lock", "Dart"],
  ["mix.lock", "Elixir"],
  ["conan.lock", "C/C++ (Conan)"],
]);
const isRequirementsFile = (name: string) => /^requirements([-_.][\w.-]+)?\.txt$/i.test(name);

/** Manifests that need a lockfile OSV can read; reported as not scanned when it's missing. */
const NEEDS_LOCKFILE: { manifest: string; lockfiles: string[]; hint: string }[] = [
  { manifest: "Cargo.toml", lockfiles: ["Cargo.lock"], hint: "run `cargo generate-lockfile`" },
  {
    manifest: "pyproject.toml",
    lockfiles: ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"],
    hint: "commit poetry.lock / uv.lock, or a pinned requirements.txt",
  },
  { manifest: "Pipfile", lockfiles: ["Pipfile.lock"], hint: "run `pipenv lock`" },
  { manifest: "build.gradle", lockfiles: ["gradle.lockfile"], hint: "enable Gradle dependency locking (`./gradlew dependencies --write-locks`)" },
  { manifest: "build.gradle.kts", lockfiles: ["gradle.lockfile"], hint: "enable Gradle dependency locking (`./gradlew dependencies --write-locks`)" },
  { manifest: "Gemfile", lockfiles: ["Gemfile.lock"], hint: "run `bundle lock`" },
  { manifest: "composer.json", lockfiles: ["composer.lock"], hint: "run `composer update --lock`" },
];

/** JS lockfiles: covered by npm audit (package-lock) or reported here only for yarn/pnpm. */
const NPM_AUDIT_LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json"]);

export interface ManifestScan {
  /** Repo-relative paths OSV-Scanner will read. */
  lockfiles: string[];
  /** Manifests we can't scan, with the reason. */
  missing: string[];
}

export async function findDependencyFiles(root: string): Promise<ManifestScan> {
  const lockfiles: string[] = [];
  const missing: string[] = [];
  const walk = async (dir: string) => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const files = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
    const rel = (name: string) => path.relative(root, path.join(dir, name)).split(path.sep).join("/");
    for (const name of files) {
      if (LOCKFILES.has(name) || isRequirementsFile(name) || name === "yarn.lock" || name === "pnpm-lock.yaml") {
        lockfiles.push(rel(name));
      }
    }
    for (const { manifest, lockfiles: locks, hint } of NEEDS_LOCKFILE) {
      if (files.has(manifest) && !locks.some((l) => files.has(l)) && ![...files].some(isRequirementsFile)) {
        missing.push(`${rel(manifest)}: no lockfile (${hint})`);
      }
    }
    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) await walk(path.join(dir, e.name));
    }
  };
  await walk(root);
  return { lockfiles, missing };
}

// ---------------------------------------------------------------- OSV JSON (v1 and v2)

interface OsvRange {
  type?: string;
  events?: { introduced?: string; fixed?: string; last_affected?: string }[];
}
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: OsvRange[] }[];
}
interface OsvGroup {
  ids: string[];
  aliases?: string[];
  max_severity?: string;
}
interface OsvPackageResult {
  package: { name: string; version: string; ecosystem: string };
  /** Lockfile groups the package belongs to, e.g. ["dev"] (poetry, pipenv, composer, Maven test scope). */
  dependency_groups?: string[];
  vulnerabilities?: OsvVuln[];
  groups?: OsvGroup[];
}
export interface OsvRaw {
  results?: { source?: { path?: string; type?: string }; packages?: OsvPackageResult[] }[];
}

const NON_PRODUCTION_GROUP = /^(dev|develop|development|test|tests|testing|lint|docs?|build-only)$/i;

/** Dev/test-only per the lockfile: every group it belongs to is a non-production one. */
export function isNonProductionGroup(groups: string[] | undefined): boolean {
  return !!groups?.length && groups.every((g) => NON_PRODUCTION_GROUP.test(g));
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityFromLabel(label: string | undefined): Severity | null {
  switch ((label ?? "").toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MODERATE":
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return null;
  }
}

function groupSeverity(group: OsvGroup, vulns: OsvVuln[]): Severity {
  const score = Number(group.max_severity);
  if (Number.isFinite(score) && score > 0) return severityFromScore(score);
  for (const v of vulns) {
    const s = severityFromLabel(v.database_specific?.severity);
    if (s) return s;
  }
  // No score published: treat as medium so it is visible but doesn't fail a "high" gate alone.
  return "medium";
}

function fixedVersions(vulns: OsvVuln[], pkg: string): string[] {
  const out = new Set<string>();
  for (const v of vulns) {
    for (const a of v.affected ?? []) {
      if (a.package?.name && a.package.name.toLowerCase() !== pkg.toLowerCase()) continue;
      for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) out.add(e.fixed);
    }
  }
  return [...out];
}

/** Prefer a GHSA/CVE id as the headline; OSV ids like PYSEC/RUSTSEC are kept as aliases. */
function primaryId(ids: string[]): string {
  return ids.find((i) => i.startsWith("GHSA-")) ?? ids.find((i) => i.startsWith("CVE-")) ?? ids[0];
}

export function osvAdapter(raw: OsvRaw, repoRoots: string[]): Finding[] {
  const findings: Finding[] = [];
  for (const result of raw.results ?? []) {
    const sourcePath = result.source?.path ?? "";
    const file = toRelative(sourcePath, repoRoots);
    if (NPM_AUDIT_LOCKFILES.has(path.posix.basename(file))) continue; // npm audit covers these
    for (const pkg of result.packages ?? []) {
      const vulns = pkg.vulnerabilities ?? [];
      // One finding per group of aliased advisories (e.g. GHSA + CVE + PYSEC for one issue).
      const groups: OsvGroup[] = pkg.groups?.length ? pkg.groups : vulns.map((v) => ({ ids: [v.id] }));
      for (const group of groups) {
        const members = vulns.filter((v) => group.ids.includes(v.id));
        if (members.length === 0) continue;
        const id = primaryId(group.ids);
        const headline = members.find((v) => v.id === id) ?? members[0];
        const fixes = fixedVersions(members, pkg.package.name);
        const aliases = [...new Set([...group.ids, ...(group.aliases ?? []), ...members.flatMap((v) => v.aliases ?? [])])].filter((a) => a !== id);
        const summary = headline.summary || headline.details?.split("\n")[0]?.slice(0, 160) || "known vulnerability";
        const devOnly = isNonProductionGroup(pkg.dependency_groups);
        const toolSeverity = groupSeverity(group, members);
        findings.push({
          skill: `osv-${pkg.package.ecosystem.toLowerCase().replace(/[^a-z0-9]+/g, "")}-${pkg.package.name}`,
          category: "backend",
          finding_id: makeFindingId({ file, rule_id: `${pkg.package.name}@${pkg.package.version}:${id}` }),
          rule_id: id,
          // Dev/test-only packages never ship, so they are capped at low (still listed).
          severity: devOnly ? "low" : toolSeverity,
          confidence: "high",
          title: `${devOnly ? "Dev dependency " : ""}${pkg.package.name} ${pkg.package.version}: ${summary}`,
          location: { file },
          raw_snippet: null,
          tool_message:
            `${pkg.package.ecosystem} package ${pkg.package.name} ${pkg.package.version} (from ${file}) is affected by ${id}` +
            `${aliases.length ? ` (also ${aliases.slice(0, 4).join(", ")})` : ""}: ${summary}.` +
            (fixes.length ? ` Fixed in ${fixes.join(", ")}.` : " No fixed version is published yet.") +
            (devOnly ? ` It is only in the lockfile's ${pkg.dependency_groups!.join("/")} group, so it does not ship with the app; rated ${toolSeverity} by the advisory.` : ""),
          metadata: {
            cwe: headline.database_specific?.cwe_ids?.[0],
            owasp: "A06:2021-Vulnerable and Outdated Components",
            ecosystem: pkg.package.ecosystem,
            package: pkg.package.name,
            version: pkg.package.version,
            aliases,
            fixedVersions: fixes,
            devOnly,
            toolSeverity,
            advisoryUrl: `https://osv.dev/vulnerability/${id}`,
          },
        });
      }
    }
  }
  return findings;
}

function toRelative(p: string, roots: string[]): string {
  if (!path.isAbsolute(p)) return p.split(path.sep).join("/").replace(/^\.\//, "");
  for (const root of roots) {
    const rel = path.relative(root, p);
    if (rel && !rel.startsWith("..")) return rel.split(path.sep).join("/");
  }
  return path.basename(p);
}

// ---------------------------------------------------------------- runner

const OSV_TIMEOUT_MS = 300000;

export async function runOsvScanner(repoDir: string): Promise<ToolRun> {
  const { lockfiles, missing } = await findDependencyFiles(repoDir);
  const scannable = lockfiles.filter((f) => !NPM_AUDIT_LOCKFILES.has(path.posix.basename(f)));
  if (scannable.length === 0) {
    // Nothing for OSV to read: fine unless a manifest is missing its lockfile.
    return { findings: [], ran: true, ...notesFor(missing) };
  }

  const check = await checkTool("osv-scanner");
  if (!check.ok) {
    const langs = [...new Set(scannable.map((f) => LOCKFILES.get(path.posix.basename(f)) ?? (isRequirementsFile(path.posix.basename(f)) ? "Python" : "JavaScript (yarn/pnpm)")))];
    return { findings: [], ran: false, error: `${check.error}; needed for ${langs.join(", ")}` };
  }
  const v2 = /version:?\s*v?2\./i.test(check.output) || /\bv?2\.\d+\.\d+/.test(check.output);
  // One explicit --lockfile per file: predictable, and skips vendored/ignored directories.
  const lockArgs = scannable.flatMap((f) => ["--lockfile", path.join(repoDir, f)]);
  const args = v2 ? ["scan", "source", "--format", "json", ...lockArgs] : ["--format", "json", ...lockArgs];
  const res = await runCommand("osv-scanner", args, { cwd: repoDir, timeoutMs: OSV_TIMEOUT_MS });

  let raw: OsvRaw;
  try {
    if (res.spawnError || res.timedOut) throw new Error();
    // Exit 1 means "vulnerabilities found"; the JSON on stdout is what matters.
    raw = JSON.parse(res.stdout) as OsvRaw;
  } catch {
    if (/no package sources found|no packages found/i.test(res.stderr + res.stdout)) {
      return { findings: [], ran: true, ...notesFor(missing) };
    }
    return { findings: [], ran: false, error: describeFailure(res, OSV_TIMEOUT_MS) };
  }
  const roots = [repoDir, await fs.realpath(repoDir)];
  return { findings: osvAdapter(raw, roots), ran: true, ...notesFor(missing) };
}

function notesFor(missing: string[]): { notes?: string[] } {
  return missing.length
    ? { notes: missing.map((m) => `Dependencies not checked for ${m}.`) }
    : {};
}
