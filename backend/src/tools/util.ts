import { spawn } from "child_process";
import path from "path";
import dotenv from "dotenv";

dotenv.config({ path: path.resolve(__dirname, "../../.env") });

function envBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(value.trim());
}

/**
 * Config sourced from environment with spec-aligned defaults.
 */
export const config = {
  port: Number(process.env.PORT ?? 4000),
  severityFloor: (process.env.SEVERITY_FLOOR ?? "low") as
    | "critical"
    | "high"
    | "medium"
    | "low",
  // LLM providers. Each is usable only when enabled AND its API key is present.
  // Default posture: Claude disabled, Gemini enabled (override via env).
  claude: {
    apiKey: process.env.ANTHROPIC_API_KEY ?? "",
    model: process.env.CLAUDE_MODEL ?? "claude-sonnet-4-6",
    enabled: envBool(process.env.CLAUDE_ENABLED, false),
  },
  gemini: {
    apiKey: process.env.GEMINI_API_KEY ?? "",
    model: process.env.GEMINI_MODEL ?? "gemini-3.6-flash",
    enabled: envBool(process.env.GEMINI_ENABLED, true),
  },
};

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
  spawnError?: string;
}

/**
 * Run a CLI tool without a shell. Never throws on non-zero exit — many scanners
 * use exit code to signal "findings present", so callers inspect the payload.
 */
export function runCommand(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; input?: string } = {}
): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, shell: false });
    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          if (!settled) {
            child.kill("SIGKILL");
          }
        }, opts.timeoutMs)
      : null;

    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ code: null, stdout, stderr, spawnError: err.message });
    });

    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });

    if (opts.input) {
      child.stdin.write(opts.input);
      child.stdin.end();
    }
  });
}

/**
 * Check whether a CLI is available on PATH.
 */
export async function toolAvailable(cmd: string): Promise<boolean> {
  const res = await runCommand(cmd, ["--version"], { timeoutMs: 5000 });
  return res.spawnError === undefined && res.code !== null;
}

/**
 * fetch with an abort timeout. Uses the global fetch (Node 18+).
 */
export async function fetchWithTimeout(
  url: string,
  opts: { timeoutMs?: number; method?: string; headers?: Record<string, string> } = {}
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15000);
  try {
    return await fetch(url, {
      method: opts.method ?? "GET",
      headers: opts.headers,
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Validate + normalize a domain into a bare hostname. Rejects anything that
 * isn't a plausible hostname to avoid SSRF-style abuse of the domain tools.
 */
export function normalizeDomain(input: string): string {
  const trimmed = input.trim().toLowerCase();
  const withoutScheme = trimmed.replace(/^https?:\/\//, "");
  const host = withoutScheme.split("/")[0].split(":")[0];
  const valid = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/.test(host);
  if (!valid) {
    throw new Error(`Invalid domain: ${input}`);
  }
  return host;
}
