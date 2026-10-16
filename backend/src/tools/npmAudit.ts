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
  fixAvailable?: boolean | { name: string; version: string };
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

export function npmAuditAdapter(
  raw: NpmAuditRaw,
  manifest = "package.json",
  category: Category = "backend"
): Finding[] {
  const vulns = raw.vulnerabilities ?? {};
  const findings: Finding[] = [];
  for (const [pkg, adv] of Object.entries(vulns)) {
    const detail = adv.via.find(
      (v): v is NpmAuditVia => typeof v === "object"
    );
    const ruleId = detail?.url ? detail.url : `npm-advisory-${pkg}`;
    findings.push({
      skill: `npm-audit-${pkg}`,
      category,
      finding_id: makeFindingId({ file: manifest, rule_id: `${pkg}:${adv.range ?? ""}` }),
      rule_id: ruleId,
      severity: mapSeverity(adv.severity),
      confidence: "high",
      title: detail?.title ?? `Vulnerable dependency: ${pkg}`,
      location: { file: manifest },
      raw_snippet: null,
      tool_message:
        detail?.title ??
        `Package ${pkg}${adv.range ? ` (${adv.range})` : ""} has a known vulnerability.`,
      metadata: {
        cwe: detail?.cwe?.[0],
        owasp: "A06:2021-Vulnerable and Outdated Components",
        package: pkg,
        range: adv.range,
        fixAvailable: adv.fixAvailable,
        advisoryUrl: detail?.url,
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

type AuditOutcome = { raw: NpmAuditRaw } | { error: string };

async function audit(cwd: string): Promise<AuditOutcome> {
  // Pin the registry so a repo's own .npmrc can't point npm at another host.
  const res = await runCommand("npm", ["audit", "--json", REGISTRY], { cwd, timeoutMs: AUDIT_TIMEOUT_MS });
  try {
    if (res.spawnError || res.timedOut) throw new Error();
    const parsed = JSON.parse(res.stdout) as NpmAuditRaw;
    if (parsed.error) return { error: parsed.error.code ?? parsed.error.summary ?? "npm audit error" };
    return { raw: parsed };
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
    for (const f of npmAuditAdapter(outcome.raw, manifest, category)) {
      if (!hasLockfile) {
        f.tool_message += ` Versions were resolved by the scanner from ${manifest} because the repo has no lockfile, so the versions you actually install may differ.`;
        f.metadata = { ...f.metadata, lockfileGenerated: true };
      }
      findings.push(f);
    }
  }
  return { findings, ran: errors.length === 0, error: errors.join("; ") || undefined };
}
