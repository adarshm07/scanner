import { promises as fs } from "fs";
import path from "path";
import { Finding, makeFindingId, Severity } from "../schema/finding";
import { runCommand } from "./util";

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

export function npmAuditAdapter(raw: NpmAuditRaw): Finding[] {
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
      finding_id: makeFindingId({ file: "package.json", rule_id: `${pkg}:${adv.range ?? ""}` }),
      rule_id: ruleId,
      severity: mapSeverity(adv.severity),
      confidence: "high",
      title: detail?.title ?? `Vulnerable dependency: ${pkg}`,
      location: { file: "package.json" },
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

export async function runNpmAudit(repoDir: string): Promise<Finding[]> {
  // Only meaningful when a package.json is present.
  try {
    await fs.access(path.join(repoDir, "package.json"));
  } catch {
    return [];
  }
  const res = await runCommand("npm", ["audit", "--json"], {
    cwd: repoDir,
    timeoutMs: 120000,
  });
  if (res.spawnError) return [];
  try {
    const parsed = JSON.parse(res.stdout) as NpmAuditRaw;
    return npmAuditAdapter(parsed);
  } catch {
    return [];
  }
}
