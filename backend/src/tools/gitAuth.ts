/**
 * Git host credentials for cloning private repositories.
 *
 * Tokens come only from the server environment (backend/.env). They are sent to git as an
 * HTTP Authorization header scoped to one host via GIT_CONFIG_* environment variables, so
 * they never appear in argv (visible in `ps`), in the clone URL, or in error messages.
 *
 * Configure with GIT_CREDENTIALS (JSON array) and/or the per-host shortcuts
 * GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN, AZURE_DEVOPS_TOKEN (see .env.example).
 */

export interface GitCredential {
  /** Hostname the token is sent to, e.g. "github.com" or "gitlab.mycompany.com". */
  host: string;
  /** HTTPS basic-auth username the host expects alongside the token. */
  username: string;
  token: string;
  /**
   * First URL path segment (user, org, group or Azure org) the token may be used for.
   * Required: a token with no owners is ignored. Use ["*"] to allow any owner on purpose.
   */
  owners: string[];
}

/** Basic-auth username each host expects with a token (see README "Private repositories"). */
const DEFAULT_USERNAMES: Record<string, string> = {
  "github.com": "x-access-token",
  "gitlab.com": "oauth2",
  "bitbucket.org": "x-bitbucket-api-token-auth",
  "dev.azure.com": "",
};

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function fromJson(raw: string | undefined): GitCredential[] {
  if (!raw?.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.warn("[git-auth] GIT_CREDENTIALS is not valid JSON; ignoring it.");
    return [];
  }
  if (!Array.isArray(parsed)) {
    console.warn("[git-auth] GIT_CREDENTIALS must be a JSON array; ignoring it.");
    return [];
  }
  const out: GitCredential[] = [];
  for (const entry of parsed as Record<string, unknown>[]) {
    const host = typeof entry?.host === "string" ? entry.host.trim().toLowerCase() : "";
    const token = typeof entry?.token === "string" ? entry.token.trim() : "";
    if (!host || !token) {
      console.warn("[git-auth] Skipping a GIT_CREDENTIALS entry without host and token.");
      continue;
    }
    const username =
      typeof entry.username === "string" ? entry.username : DEFAULT_USERNAMES[host] ?? "oauth2";
    const owners = Array.isArray(entry.owners)
      ? entry.owners.filter((o): o is string => typeof o === "string").map((o) => o.trim().toLowerCase())
      : [];
    out.push({ host, username, token, owners });
  }
  return out;
}

function fromShortcuts(env: NodeJS.ProcessEnv): GitCredential[] {
  const out: GitCredential[] = [];
  const add = (host: string | undefined, token: string | undefined, username: string | undefined, owners: string | undefined) => {
    const h = host?.trim().toLowerCase();
    const t = token?.trim();
    if (!h || !t) return;
    out.push({ host: h, token: t, username: username ?? DEFAULT_USERNAMES[h] ?? "oauth2", owners: list(owners) });
  };
  add("github.com", env.GITHUB_TOKEN, undefined, env.GITHUB_OWNERS);
  add(env.GITLAB_HOST || "gitlab.com", env.GITLAB_TOKEN, undefined, env.GITLAB_OWNERS);
  add("bitbucket.org", env.BITBUCKET_TOKEN, env.BITBUCKET_USERNAME, env.BITBUCKET_OWNERS);
  add("dev.azure.com", env.AZURE_DEVOPS_TOKEN, undefined, env.AZURE_DEVOPS_OWNERS);
  return out;
}

/**
 * Configured tokens that are allowed to be used. GIT_CREDENTIALS entries win over shortcuts
 * for the same host. A token without owners is ignored: variables like GITHUB_TOKEN are often
 * exported in developers' shells for other tools, and silently using one would let anyone who
 * can reach the API scan every repo it can read.
 */
export function loadGitCredentials(env: NodeJS.ProcessEnv = process.env): GitCredential[] {
  const merged = new Map<string, GitCredential>();
  for (const c of fromShortcuts(env)) merged.set(c.host, c);
  for (const c of fromJson(env.GIT_CREDENTIALS)) merged.set(c.host, c);
  return [...merged.values()].filter((c) => c.owners.length > 0);
}

/** Hosts whose token is set but ignored because no owners are listed (for the startup log). */
export function ignoredGitCredentials(env: NodeJS.ProcessEnv = process.env): string[] {
  const merged = new Map<string, GitCredential>();
  for (const c of fromShortcuts(env)) merged.set(c.host, c);
  for (const c of fromJson(env.GIT_CREDENTIALS)) merged.set(c.host, c);
  return [...merged.values()].filter((c) => c.owners.length === 0).map((c) => c.host);
}

// Read lazily: this module can load before dotenv runs.
let cached: GitCredential[] | null = null;
function credentials(): GitCredential[] {
  if (!cached) cached = loadGitCredentials();
  return cached;
}

/** Test hook: reload credentials from the given environment. */
export function resetGitCredentials(env?: NodeJS.ProcessEnv): void {
  cached = env ? loadGitCredentials(env) : null;
}

function ownerOf(url: URL): string {
  return decodeURIComponent(url.pathname.split("/").filter(Boolean)[0] ?? "").toLowerCase();
}

/** The credential that applies to this repository URL, if any. */
export function credentialFor(repoUrl: string): GitCredential | undefined {
  let url: URL;
  try {
    url = new URL(repoUrl);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:") return undefined;
  const host = url.hostname.toLowerCase();
  const owner = ownerOf(url);
  return credentials().find(
    (c) => c.host === host && (c.owners.includes("*") || c.owners.includes(owner))
  );
}

/**
 * Environment for every git process (and tools that spawn git, like gitleaks) working on
 * this repository. Never prompts; adds an Authorization header only for a matching host.
 */
export function gitEnv(repoUrl: string): Record<string, string> {
  const env: Record<string, string> = {
    GIT_TERMINAL_PROMPT: "0", // fail instead of waiting for a username prompt
    GCM_INTERACTIVE: "never", // Git Credential Manager: never open a login window
  };
  const cred = credentialFor(repoUrl);
  if (!cred) return env;
  const basic = Buffer.from(`${cred.username}:${cred.token}`).toString("base64");
  env.GIT_CONFIG_COUNT = "1";
  env.GIT_CONFIG_KEY_0 = `http.https://${cred.host}/.extraheader`;
  env.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${basic}`;
  return env;
}

/** Replace every configured token (raw and basic-auth encoded) with "***". */
export function redactSecrets(text: string): string {
  let out = text;
  for (const c of credentials()) {
    const basic = Buffer.from(`${c.username}:${c.token}`).toString("base64");
    for (const secret of [c.token, basic]) {
      if (secret.length >= 8) out = out.split(secret).join("***");
    }
  }
  return out;
}

/** Startup summary without secrets, e.g. ["github.com (owners: adarshm07)"]. */
export function describeGitCredentials(): string[] {
  return credentials().map(
    (c) => `${c.host} (${c.owners.includes("*") ? "any owner" : `owners: ${c.owners.join(", ")}`})`
  );
}
