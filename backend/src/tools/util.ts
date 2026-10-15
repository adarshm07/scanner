import { spawn } from "child_process";
import path from "path";
import dotenv from "dotenv";
import { Agent, fetch, Response } from "undici";
import { allowPrivateTargets, assertIpLiteralAllowed, assertPublicHost, guardedLookup } from "./netGuard";

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
  openai: {
    apiKey: process.env.OPENAI_API_KEY ?? "",
    baseURL: process.env.OPENAI_BASE_URL ?? "",
    model: process.env.OPENAI_MODEL ?? "global-openai-chat-models/gpt-4-1-nano",
    enabled: envBool(process.env.OPENAI_ENABLED, false),
  },
  repoHostAllowlist: new Set(
    (process.env.REPO_HOST_ALLOWLIST ?? "github.com,gitlab.com,bitbucket.org,dev.azure.com")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
  ),
  // Self-hosted git servers that resolve to internal addresses (e.g. a company GitLab).
  // Only these hosts skip the private-address check; ALLOW_PRIVATE_TARGETS stays off.
  repoPrivateHosts: new Set(
    (process.env.REPO_PRIVATE_HOSTS ?? "")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
  ),
};

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
  spawnError?: string;
  timedOut?: boolean;
}

/**
 * Run a CLI tool without a shell. Never throws on non-zero exit — many scanners
 * use exit code to signal "findings present", so callers inspect the payload.
 */
export function runCommand(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; input?: string; env?: Record<string, string> } = {}
): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      shell: false,
      env: opts.env ? { ...process.env, ...opts.env } : process.env,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          if (!settled) {
            timedOut = true;
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
      resolve({ code, stdout, stderr, ...(timedOut ? { timedOut } : {}) });
    });

    if (opts.input) {
      child.stdin.write(opts.input);
      child.stdin.end();
    }
  });
}

/** Short reason a command produced no usable output, for "not scanned" warnings. */
export function describeFailure(res: CommandResult, timeoutMs?: number): string {
  if (res.spawnError) return res.spawnError;
  if (res.timedOut) return `timed out${timeoutMs ? ` after ${Math.round(timeoutMs / 1000)}s` : ""}`;
  const lastLine = res.stderr.trim().split("\n").pop()?.trim();
  return (lastLine || `exited with code ${res.code}`).slice(0, 200);
}

export type ToolCheck = { ok: true } | { ok: false; error: string };

/** Distinguishes a missing CLI from one that hangs or fails, so warnings point at the right fix. */
export async function checkTool(cmd: string, env?: Record<string, string>): Promise<ToolCheck> {
  const res = await runCommand(cmd, ["--version"], { timeoutMs: 15000, env });
  if (res.spawnError) {
    return { ok: false, error: /ENOENT/.test(res.spawnError) ? `${cmd} not installed` : res.spawnError };
  }
  if (res.timedOut) return { ok: false, error: `${cmd} --version timed out` };
  if (res.code === 0) return { ok: true };
  const firstLine = res.stderr.trim().split("\n")[0]?.trim().slice(0, 160);
  return { ok: false, error: `${cmd} --version exited ${res.code}${firstLine ? `: ${firstLine}` : ""}` };
}

const guardedAgent = new Agent({ connect: { lookup: guardedLookup } });

/**
 * fetch with an abort timeout. Connections to private/internal addresses are refused.
 */
export async function fetchWithTimeout(
  url: string,
  opts: { timeoutMs?: number; method?: string; headers?: Record<string, string> } = {}
): Promise<Response> {
  assertIpLiteralAllowed(new URL(url).hostname);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15000);
  try {
    return await fetch(url, {
      method: opts.method ?? "GET",
      headers: opts.headers,
      redirect: "manual",
      signal: controller.signal,
      dispatcher: guardedAgent,
    });
  } finally {
    clearTimeout(timer);
  }
}

const LOCAL_TARGET = /^(localhost|\d{1,3}(\.\d{1,3}){3})(:\d{1,5})?$/;

/** localhost or IPv4, optionally with a port; only accepted with ALLOW_PRIVATE_TARGETS. */
export function isLocalTarget(host: string): boolean {
  return LOCAL_TARGET.test(host);
}

/** Local fixtures serve plain http; everything else is scanned over https. */
export function targetOrigin(host: string): string {
  return `${isLocalTarget(host) ? "http" : "https"}://${host}`;
}

/**
 * Validate + normalize a domain into a bare hostname. Rejects anything that
 * isn't a plausible hostname to avoid SSRF-style abuse of the domain tools.
 */
export function normalizeDomain(input: string): string {
  const trimmed = input.trim().toLowerCase();
  const withoutScheme = trimmed.replace(/^https?:\/\//, "");
  const hostWithPort = withoutScheme.split("/")[0];
  if (allowPrivateTargets() && isLocalTarget(hostWithPort)) {
    return hostWithPort;
  }
  const host = hostWithPort.split(":")[0];
  const valid = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/.test(host);
  if (!valid) {
    throw new Error(`Invalid domain: ${input}`);
  }
  return host;
}

/**
 * Accept only credential-free https URLs on an allowlisted host that resolves publicly
 * (or is listed in REPO_PRIVATE_HOSTS).
 */
export async function validateRepoUrl(input: unknown): Promise<string> {
  if (typeof input !== "string") throw new Error("Valid repoUrl is required.");
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error("Valid repoUrl is required.");
  }
  if (url.protocol !== "https:") throw new Error("repoUrl must use https://.");
  // Azure DevOps "Clone" URLs carry the org as a username (https://org@dev.azure.com/...);
  // it isn't a credential, so drop it. Anything with a password is still refused.
  if (url.username && !url.password && url.hostname.toLowerCase() === "dev.azure.com") {
    url.username = "";
  }
  if (url.username || url.password) {
    throw new Error("repoUrl must not contain credentials. Configure tokens in backend/.env instead.");
  }
  if (url.port) throw new Error("repoUrl must not specify a port.");
  const host = url.hostname.toLowerCase();
  if (!config.repoHostAllowlist.has(host)) {
    throw new Error(`Repository host not allowed: ${host}`);
  }
  if (!config.repoPrivateHosts.has(host)) await assertPublicHost(host);
  url.hash = "";
  url.search = "";
  return url.toString();
}

/** Git ref names safe to pass as arguments (no leading dash, no range syntax). */
export function validateRef(input: unknown, name: string): string | undefined {
  if (input === undefined || input === null || input === "") return undefined;
  if (
    typeof input !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(input) ||
    input.includes("..") ||
    input.endsWith(".lock") ||
    input.endsWith("/")
  ) {
    throw new Error(`Invalid ${name}.`);
  }
  return input;
}
