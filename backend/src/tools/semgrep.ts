import path from "path";
import { Finding, makeFindingId, Severity, Confidence } from "../schema/finding";
import { checkTool, describeFailure, runCommand } from "./util";
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

/** Repo-relative path ("src/a.js"): finding IDs, diff filtering and links all depend on it. */
function relativePath(file: string, repoDir?: string): string {
  let rel = repoDir && path.isAbsolute(file) ? path.relative(repoDir, file) : file;
  rel = rel.split(path.sep).join("/").replace(/^(\.\/)+/, "");
  return rel;
}

export function semgrepAdapter(raw: SemgrepRaw, repoDir?: string): Finding[] {
  const results = raw.results ?? [];
  return results.map((r) => {
    const meta = r.extra?.metadata ?? {};
    const file = relativePath(r.path, repoDir);
    return {
      skill: `semgrep-${r.check_id.split(".").pop() ?? "rule"}`,
      category: "backend",
      finding_id: makeFindingId({
        file,
        line_start: r.start.line,
        rule_id: r.check_id,
      }),
      rule_id: r.check_id,
      severity: mapSeverity(r.extra?.severity),
      confidence: mapConfidence(meta.confidence),
      title: r.extra?.message?.split("\n")[0] ?? r.check_id,
      location: {
        file,
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
// Without these, semgrep phones home on startup and hangs ~30s when offline.
const SEMGREP_ENV = { SEMGREP_ENABLE_VERSION_CHECK: "0", SEMGREP_SEND_METRICS: "off" };

export async function runSemgrep(repoDir: string): Promise<ToolRun> {
  const check = await checkTool("semgrep", SEMGREP_ENV);
  if (!check.ok) return { findings: [], ran: false, error: check.error };
  // A local rules file (SEMGREP_CONFIG) lets air-gapped runners skip the registry download.
  const rules = process.env.SEMGREP_CONFIG?.trim() || "p/security-audit";
  const res = await runCommand(
    "semgrep",
    // Target "." (we run inside the repo) so semgrep reports repo-relative paths.
    ["--config", rules, "--json", "--quiet", "--metrics=off", "."],
    { cwd: repoDir, timeoutMs: SEMGREP_TIMEOUT_MS, env: SEMGREP_ENV }
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
  return { findings: semgrepAdapter(parsed, repoDir), ran: true };
}
