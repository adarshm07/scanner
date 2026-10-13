import { promises as fs } from "fs";
import path from "path";
import { Finding, makeFindingId, Severity } from "../schema/finding";
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

export function npmAuditAdapter(raw: NpmAuditRaw, manifest = "package.json"): Finding[] {
  const vulns = raw.vulnerabilities ?? {};
  const findings: Finding[] = [];
  for (const [pkg, adv] of Object.entries(vulns)) {
    const detail = adv.via.find(
      (v): v is NpmAuditVia => typeof v === "object"
    );
    const ruleId = detail?.url ? detail.url : `npm-advisory-${pkg}`;
    findings.push({
      skill: `npm-audit-${pkg}`,
      category: "backend",
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

interface ManifestDir {
  dir: string;
  hasLockfile: boolean;
}

async function findManifestDirs(root: string): Promise<ManifestDir[]> {
  const out: ManifestDir[] = [];
  const walk = async (dir: string) => {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const files = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
    if (files.has("package.json")) {
      out.push({ dir, hasLockfile: LOCKFILES.some((f) => files.has(f)) });
    }
    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) await walk(path.join(dir, e.name));
    }
  };
  await walk(root);
  return out;
}

export async function runNpmAudit(repoDir: string): Promise<ToolRun> {
  const manifests = await findManifestDirs(repoDir);
  if (manifests.length === 0) return { findings: [], ran: true };
  const lockDirs = manifests.filter((m) => m.hasLockfile).map((m) => m.dir);
  // Workspace members share the root lockfile; auditing them separately fails with ENOLOCK.
  const coveredByAncestor = (dir: string) =>
    lockDirs.some((lock) => lock !== dir && dir.startsWith(lock + path.sep));

  const findings: Finding[] = [];
  const errors: string[] = [];
  for (const { dir, hasLockfile } of manifests) {
    const rel = path.relative(repoDir, dir).split(path.sep).join("/") || ".";
    if (!hasLockfile) {
      if (!coveredByAncestor(dir)) errors.push(`${rel}: no package-lock.json`);
      continue;
    }
    const res = await runCommand(
      "npm",
      // Pin the registry so a repo's own .npmrc can't point npm at another host.
      ["audit", "--json", "--registry=https://registry.npmjs.org/"],
      { cwd: dir, timeoutMs: AUDIT_TIMEOUT_MS }
    );
    try {
      if (res.spawnError || res.timedOut) throw new Error();
      const parsed = JSON.parse(res.stdout) as NpmAuditRaw;
      if (parsed.error) {
        errors.push(`${rel}: ${parsed.error.code ?? parsed.error.summary ?? "npm audit error"}`);
        continue;
      }
      findings.push(...npmAuditAdapter(parsed, path.posix.join(rel, "package.json")));
    } catch {
      errors.push(`${rel}: ${describeFailure(res, AUDIT_TIMEOUT_MS)}`);
    }
  }
  return { findings, ran: errors.length === 0, error: errors.join("; ") || undefined };
}
