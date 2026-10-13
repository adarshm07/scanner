import { Finding, makeFindingId, Severity, Confidence } from "../schema/finding";
import { describeFailure, runCommand, toolAvailable } from "./util";
import { ToolRun } from "./types";

/**
 * semgrep — SAST pattern matching (repo mode). Uses the default p/security-audit
 * ruleset. Adapter isolates all semgrep-specific JSON parsing.
 */

interface SemgrepRawResult {
  check_id: string;
  path: string;
  start: { line: number };
  end: { line: number };
  extra?: {
    message?: string;
    severity?: string; // ERROR | WARNING | INFO
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      confidence?: string;
      category?: string;
    };
  };
}

interface SemgrepRaw {
  results?: SemgrepRawResult[];
  errors?: { level?: string; message?: string; type?: string | unknown[] }[];
}

function mapSeverity(semgrep?: string): Severity {
  switch ((semgrep ?? "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    default:
      return "low";
  }
}

function mapConfidence(value?: string): Confidence {
  switch ((value ?? "").toUpperCase()) {
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function first(value?: string | string[]): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

export function semgrepAdapter(raw: SemgrepRaw): Finding[] {
  const results = raw.results ?? [];
  return results.map((r) => {
    const meta = r.extra?.metadata ?? {};
    return {
      skill: `semgrep-${r.check_id.split(".").pop() ?? "rule"}`,
      category: "backend",
      finding_id: makeFindingId({
        file: r.path,
        line_start: r.start.line,
        rule_id: r.check_id,
      }),
      rule_id: r.check_id,
      severity: mapSeverity(r.extra?.severity),
      confidence: mapConfidence(meta.confidence),
      title: r.extra?.message?.split("\n")[0] ?? r.check_id,
      location: {
        file: r.path,
        line_start: r.start.line,
        line_end: r.end.line,
      },
      raw_snippet: null,
      tool_message: r.extra?.message ?? r.check_id,
      metadata: {
        cwe: first(meta.cwe),
        owasp: first(meta.owasp),
        category: meta.category,
      },
    } satisfies Finding;
  });
}

const SEMGREP_TIMEOUT_MS = 180000;

export async function runSemgrep(repoDir: string): Promise<ToolRun> {
  if (!(await toolAvailable("semgrep"))) {
    return { findings: [], ran: false, error: "semgrep not installed" };
  }
  const res = await runCommand(
    "semgrep",
    ["--config", "p/security-audit", "--json", "--quiet", repoDir],
    { cwd: repoDir, timeoutMs: SEMGREP_TIMEOUT_MS }
  );
  let parsed: SemgrepRaw;
  try {
    parsed = JSON.parse(res.stdout) as SemgrepRaw;
  } catch {
    return { findings: [], ran: false, error: describeFailure(res, SEMGREP_TIMEOUT_MS) };
  }
  // Exit 0/1 is a completed scan (per-file parse errors are reported but non-fatal); anything else is fatal.
  if (res.code !== 0 && res.code !== 1) {
    const message = parsed.errors?.find((e) => e.message)?.message?.split("\n")[0];
    return { findings: [], ran: false, error: (message ?? describeFailure(res, SEMGREP_TIMEOUT_MS)).slice(0, 200) };
  }
  return { findings: semgrepAdapter(parsed), ran: true };
}
