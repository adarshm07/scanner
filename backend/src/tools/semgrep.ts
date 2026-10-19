import path from "path";
import { Finding, makeFindingId, Severity, Confidence } from "../schema/finding";
import { checkTool, CommandResult, describeFailure, runCommand } from "./util";
import { ToolRun } from "./types";

/**
 * semgrep — SAST pattern matching (repo mode). Runs the registry rulesets below (semgrep
 * only applies the rules for languages present in the repo) plus Scanner-X's own rules in
 * backend/rules/scanner-x.yml. Adapter isolates all semgrep-specific JSON parsing.
 */

/** Registry rulesets used unless SEMGREP_CONFIG (comma-separated) is set. */
export const DEFAULT_RULESETS = [
  "p/security-audit",
  "p/owasp-top-ten",
  "p/javascript",
  "p/typescript",
  "p/python",
  "p/java",
  "p/golang",
];

/** Scanner-X's own rules (NoSQL $where injection, autoescape off, missing CSRF, SSRF). */
export const CUSTOM_RULES = path.resolve(__dirname, "../../rules/scanner-x.yml");

export function semgrepConfigs(env: NodeJS.ProcessEnv = process.env): string[] {
  const configured = (env.SEMGREP_CONFIG ?? "")
    .split(",")
    .map((c) => c.trim())
    .filter(Boolean);
  const base = configured.length ? configured : DEFAULT_RULESETS;
  const custom = env.SCANNER_X_CUSTOM_RULES === "0" ? [] : [CUSTOM_RULES];
  return [...new Set([...base, ...custom])];
}

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
    // Newer registry rules use CRITICAL/HIGH/MEDIUM/LOW; classic ones ERROR/WARNING/INFO.
    case "CRITICAL":
      return "critical";
    case "ERROR":
    case "HIGH":
      return "high";
    case "WARNING":
    case "MEDIUM":
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

/**
 * semgrep prefixes rules loaded from a local file with that file's path, so a Scanner-X rule
 * comes back as "Users.alice.work.scanner.backend.rules.scanner-x.ssrf-user-controlled-url".
 * That leaks the runner's home directory into reports and LLM prompts, and makes finding IDs
 * differ between machines. Keep just the rule's own id.
 */
export function normalizeRuleId(checkId: string): string {
  const own = /(?:^|\.)(scanner-x\.[A-Za-z0-9_-]+)$/.exec(checkId);
  return own ? own[1] : checkId;
}

export function semgrepAdapter(raw: SemgrepRaw, repoDir?: string): Finding[] {
  const results = raw.results ?? [];
  return results.map((r) => {
    const meta = r.extra?.metadata ?? {};
    const file = relativePath(r.path, repoDir);
    const ruleId = normalizeRuleId(r.check_id);
    return {
      skill: `semgrep-${ruleId.split(".").pop() ?? "rule"}`,
      category: "backend",
      finding_id: makeFindingId({
        file,
        line_start: r.start.line,
        rule_id: ruleId,
      }),
      rule_id: ruleId,
      severity: mapSeverity(r.extra?.severity),
      confidence: mapConfidence(meta.confidence),
      title: r.extra?.message?.split("\n")[0] ?? ruleId,
      location: {
        file,
        line_start: r.start.line,
        line_end: r.end.line,
      },
      raw_snippet: null,
      tool_message: r.extra?.message ?? ruleId,
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
  if (!check.ok) return { findings: [], ran: false, error: classifySemgrepFailure({ code: null, stdout: "", stderr: "", spawnError: check.error }) };
  // A local rules file or folder (SEMGREP_CONFIG) lets air-gapped runners skip the registry download.
  const configs = semgrepConfigs();
  const res = await runCommand(
    "semgrep",
    // Target "." (we run inside the repo) so semgrep reports repo-relative paths. No --quiet:
    // its stderr is what explains a failure (e.g. the registry being unreachable).
    [...configs.flatMap((c) => ["--config", c]), "--json", "--metrics=off", "."],
    { cwd: repoDir, timeoutMs: SEMGREP_TIMEOUT_MS, env: SEMGREP_ENV }
  );
  let parsed: SemgrepRaw;
  try {
    parsed = JSON.parse(res.stdout) as SemgrepRaw;
  } catch {
    return { findings: [], ran: false, error: classifySemgrepFailure(res) };
  }
  // Exit 0/1 is a completed scan (per-file parse errors are reported but non-fatal); anything else is fatal.
  if (res.code !== 0 && res.code !== 1) {
    const message = parsed.errors?.find((e) => e.message)?.message?.split("\n")[0];
    return { findings: [], ran: false, error: classifySemgrepFailure(res, message) };
  }
  return { findings: semgrepAdapter(parsed, repoDir), ran: true };
}

const OFFLINE_HINT =
  "To scan without semgrep.dev, set SEMGREP_CONFIG to a local rules file or folder (for example a clone of https://github.com/semgrep/semgrep-rules).";

/**
 * Turn a failed semgrep run into a reason a person can act on, instead of "exited with
 * code 2". Exported for tests.
 */
export function classifySemgrepFailure(res: CommandResult, jsonMessage?: string): string {
  const text = `${res.spawnError ?? ""}\n${jsonMessage ?? ""}\n${res.stderr}`;
  if (/pysemgrep/i.test(text)) {
    return "semgrep is installed but can't start its pysemgrep helper (it isn't on the PATH Scanner-X runs with). Reinstall with `pipx install semgrep` or `brew install semgrep`, or add pysemgrep's folder to PATH.";
  }
  if (/CERTIFICATE_VERIFY_FAILED|SSLError|self.signed certificate/i.test(text)) {
    return `semgrep couldn't download its rules from semgrep.dev: TLS verification failed, usually a TLS-inspecting proxy. Point REQUESTS_CA_BUNDLE (or SSL_CERT_FILE) at your proxy's CA bundle. ${OFFLINE_HINT}`;
  }
  if (/semgrep\.dev|HTTPSConnectionPool|ProxyError|ConnectionError|Max retries exceeded|Name or service not known|Temporary failure in name resolution|getaddrinfo|Failed to download config/i.test(text)) {
    return `semgrep couldn't download its rules from semgrep.dev (no network access, or a proxy or firewall blocked it). ${OFFLINE_HINT}`;
  }
  if (/invalid configuration|invalid rule|does not exist|no such file|failed to parse|yaml/i.test(text)) {
    const line = (jsonMessage ?? text.split("\n").find((l) => /invalid|does not exist|no such file|failed to parse/i.test(l)) ?? "").trim();
    return `semgrep rejected its rules config${line ? ` (${line.slice(0, 160)})` : ""}. Check SEMGREP_CONFIG: it takes registry rulesets (p/...), local rule files or folders, comma-separated.`;
  }
  if (res.timedOut) return `semgrep timed out after ${Math.round(SEMGREP_TIMEOUT_MS / 1000)}s; try a diff scan (--base) on large repos.`;
  if (jsonMessage) return jsonMessage.slice(0, 200);
  // Skip Python traceback noise and use the last meaningful line.
  const meaningful = res.stderr
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !/^(Traceback|File "|\^+|~+|During handling|The above exception)/.test(l));
  return (meaningful.pop() ?? describeFailure(res, SEMGREP_TIMEOUT_MS)).slice(0, 200);
}
