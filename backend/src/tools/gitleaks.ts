import { promises as fs } from "fs";
import path from "path";
import { Finding, makeFindingId } from "../schema/finding";
import { runCommand, toolAvailable } from "./util";

/**
 * gitleaks — secret detection (repo mode).
 *
 * Adapter isolates all gitleaks-specific JSON parsing. The rest of the pipeline
 * only ever sees the universal Finding shape.
 */

interface GitleaksRaw {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  EndLine?: number;
  Secret?: string;
  Match?: string;
  Tags?: string[];
}

export function gitleaksAdapter(raw: GitleaksRaw[]): Finding[] {
  return raw.map((r) => {
    const ruleId = r.RuleID ?? "gitleaks-generic";
    const file = r.File ?? "unknown";
    const line = r.StartLine ?? 0;
    return {
      skill: `gitleaks-${ruleId}`,
      category: "backend",
      finding_id: makeFindingId({ file, line_start: line, rule_id: ruleId }),
      rule_id: ruleId,
      // Leaked secrets are treated as high severity by default.
      severity: "high",
      confidence: "medium",
      title: r.Description ?? `Potential secret detected (${ruleId})`,
      location: {
        file,
        line_start: r.StartLine,
        line_end: r.EndLine ?? r.StartLine,
      },
      raw_snippet: null,
      tool_message: r.Description ?? "Hardcoded secret detected by gitleaks.",
      metadata: {
        cwe: "CWE-798",
        owasp: "A07:2021-Identification and Authentication Failures",
        tags: r.Tags ?? [],
      },
    } satisfies Finding;
  });
}

/**
 * Run gitleaks against a repo directory. Returns [] if the CLI is not installed
 * (no fabricated data — install gitleaks to enable secret scanning).
 */
export async function runGitleaks(
  repoDir: string,
  opts: { fullHistory?: boolean; logOpts?: string } = {}
): Promise<Finding[]> {
  // A commit range (diff mode) always scans history, so secrets added then removed in the PR are caught.
  const scanGit = opts.fullHistory === true || !!opts.logOpts;
  if (!(await toolAvailable("gitleaks"))) {
    return [];
  }
  const reportPath = path.join(repoDir, ".scanner-x-gitleaks.json");
  const args = scanGit
    ? [
        "git",
        ...(opts.logOpts ? [`--log-opts=${opts.logOpts}`] : []),
        "--report-format", "json", "--report-path", reportPath, repoDir,
      ]
    : ["detect", "--source", repoDir, "--no-git", "--report-format", "json", "--report-path", reportPath];
  await runCommand(
    "gitleaks",
    args,
    { cwd: repoDir, timeoutMs: scanGit ? 600000 : 120000 }
  );
  try {
    const content = await fs.readFile(reportPath, "utf8");
    await fs.rm(reportPath, { force: true });
    const parsed = JSON.parse(content) as GitleaksRaw[];
    return gitleaksAdapter(Array.isArray(parsed) ? parsed : []);
  } catch {
    return [];
  }
}
