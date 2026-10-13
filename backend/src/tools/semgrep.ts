import { Finding, makeFindingId, Severity, Confidence } from "../schema/finding";
import { runCommand, toolAvailable } from "./util";

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

export async function runSemgrep(repoDir: string): Promise<Finding[]> {
  if (!(await toolAvailable("semgrep"))) {
    return [];
  }
  const res = await runCommand(
    "semgrep",
    ["--config", "p/security-audit", "--json", "--quiet", repoDir],
    { cwd: repoDir, timeoutMs: 180000 }
  );
  try {
    const parsed = JSON.parse(res.stdout) as SemgrepRaw;
    return semgrepAdapter(parsed);
  } catch {
    return [];
  }
}
