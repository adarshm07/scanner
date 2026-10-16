import { promises as fs } from "fs";
import path from "path";
import { Finding, makeFindingId } from "../schema/finding";
import { checkTool, describeFailure, runCommand } from "./util";
import { ToolRun } from "./types";
import { attachSecret } from "./secrets";

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
    const finding = toFinding(r);
    // Kept only in memory (non-enumerable) so the report step can mask it everywhere.
    attachSecret(finding, r.Secret);
    return finding;
  });
}

function toFinding(r: GitleaksRaw): Finding {
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
}

/**
 * Run gitleaks against a repo directory. Exit code 1 means either "leaks found" or a
 * fatal error, so success is judged by whether a parseable report was written.
 */
export async function runGitleaks(
  repoDir: string,
  opts: { fullHistory?: boolean; logOpts?: string; env?: Record<string, string> } = {}
): Promise<ToolRun> {
  // A commit range (diff mode) always scans history, so secrets added then removed in the PR are caught.
  const scanGit = opts.fullHistory === true || !!opts.logOpts;
  const check = await checkTool("gitleaks");
  if (!check.ok) return { findings: [], ran: false, error: check.error };
  const reportPath = path.join(repoDir, ".scanner-x-gitleaks.json");
  await fs.rm(reportPath, { force: true });
  const args = scanGit
    ? [
        "git",
        ...(opts.logOpts ? [`--log-opts=${opts.logOpts}`] : []),
        "--report-format", "json", "--report-path", reportPath, repoDir,
      ]
    : ["detect", "--source", repoDir, "--no-git", "--report-format", "json", "--report-path", reportPath];
  const timeoutMs = scanGit ? 600000 : 120000;
  // gitleaks runs git internally; pass the repo's git env so lazy blob fetches can authenticate.
  const res = await runCommand("gitleaks", args, { cwd: repoDir, timeoutMs, env: opts.env });
  if (res.spawnError || res.timedOut) {
    return { findings: [], ran: false, error: describeFailure(res, timeoutMs) };
  }
  try {
    const content = await fs.readFile(reportPath, "utf8");
    await fs.rm(reportPath, { force: true });
    const parsed = JSON.parse(content) as GitleaksRaw[];
    if (!Array.isArray(parsed)) throw new Error("unexpected report format");
    return { findings: gitleaksAdapter(parsed), ran: true };
  } catch {
    return { findings: [], ran: false, error: describeFailure(res, timeoutMs) };
  }
}
