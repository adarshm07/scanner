import { randomBytes } from "crypto";
import type { Response } from "undici";
import { CheckResult, Finding, makeFindingId, Severity } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout, targetOrigin } from "./util";

/**
 * Exposed sensitive files (domain mode). Requests well-known paths that should never be
 * public (VCS metadata, env files, backups, debug endpoints, source maps) and reports a
 * path only when the body is recognisably that kind of file. Many sites answer 200 for any
 * path, so a random path is requested first and responses that look like it are ignored.
 */

const MAX_REDIRECTS = 3;
const REQUEST_TIMEOUT_MS = 4000;
/** Only the start of a file is needed to recognise it; never download a whole backup. */
const MAX_BYTES = 64 * 1024;
const CONCURRENCY = 8;

interface Probe {
  path: string;
  /** What the file is, for titles ("Git repository config"). */
  what: string;
  severity: Severity;
  /** Why it matters. */
  impact: string;
  /** True for files that are legitimately HTML (status pages). */
  html?: boolean;
  test: (body: Buffer, text: string) => boolean;
}

const startsWith = (body: Buffer, magic: string) => body.subarray(0, magic.length).equals(Buffer.from(magic, "binary"));
const ENV_LINE = /^[A-Z][A-Z0-9_]*=.*$/m;
const SQL = /CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump/i;
const OPENAPI = /"(openapi|swagger)"\s*:\s*"\d/;

const SOURCE = "Attackers can download the source and its full history, often including credentials.";
const SECRETS = "Contains configuration such as database passwords, API keys and signing secrets.";
const BACKUP = "A copy of the site or database that can include source code, user data and credentials.";

export const PROBES: Probe[] = [
  { path: ".git/config", what: "Git repository config", severity: "critical", impact: SOURCE, test: (_, t) => /\[core\]|\[remote\b/i.test(t) },
  { path: ".git/HEAD", what: "Git repository HEAD", severity: "critical", impact: SOURCE, test: (_, t) => /^\s*ref:\s*\S+/m.test(t) || /^\s*[0-9a-f]{40}\s*$/im.test(t) },
  { path: ".svn/wc.db", what: "Subversion working copy database", severity: "high", impact: SOURCE, test: (b) => startsWith(b, "SQLite format 3\0") },
  { path: ".env", what: "environment file", severity: "critical", impact: SECRETS, test: (_, t) => ENV_LINE.test(t) },
  { path: ".env.local", what: "environment file", severity: "critical", impact: SECRETS, test: (_, t) => ENV_LINE.test(t) },
  { path: ".env.production", what: "environment file", severity: "critical", impact: SECRETS, test: (_, t) => ENV_LINE.test(t) },
  { path: ".env.backup", what: "environment file backup", severity: "critical", impact: SECRETS, test: (_, t) => ENV_LINE.test(t) },
  { path: "wp-config.php.bak", what: "WordPress config backup", severity: "critical", impact: SECRETS, test: (_, t) => /DB_PASSWORD/.test(t) },
  { path: "wp-config.php~", what: "WordPress config backup", severity: "critical", impact: SECRETS, test: (_, t) => /DB_PASSWORD/.test(t) },
  { path: "config.php.bak", what: "PHP config backup", severity: "high", impact: SECRETS, test: (_, t) => /<\?php/.test(t) && /pass(word)?/i.test(t) },
  { path: ".npmrc", what: "npm config with registry token", severity: "high", impact: "Contains a registry token that can publish or read private packages.", test: (_, t) => /_authToken\s*=|_auth\s*=/.test(t) },
  { path: ".htpasswd", what: "password file", severity: "high", impact: "Password hashes that can be cracked offline.", test: (_, t) => /^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)/m.test(t) },
  { path: "docker-compose.yml", what: "Docker Compose file", severity: "medium", impact: "Reveals internal services, image versions and often environment secrets.", test: (_, t) => /^services:\s*$/m.test(t) && /\b(image|build):/.test(t) },
  { path: "backup.zip", what: "site backup archive", severity: "high", impact: BACKUP, test: (b) => startsWith(b, "PK\x03\x04") },
  { path: "site.zip", what: "site backup archive", severity: "high", impact: BACKUP, test: (b) => startsWith(b, "PK\x03\x04") },
  { path: "www.zip", what: "site backup archive", severity: "high", impact: BACKUP, test: (b) => startsWith(b, "PK\x03\x04") },
  { path: "backup.tar.gz", what: "site backup archive", severity: "high", impact: BACKUP, test: (b) => startsWith(b, "\x1f\x8b") },
  { path: "backup.sql", what: "database dump", severity: "critical", impact: BACKUP, test: (_, t) => SQL.test(t) },
  { path: "dump.sql", what: "database dump", severity: "critical", impact: BACKUP, test: (_, t) => SQL.test(t) },
  { path: "db.sql", what: "database dump", severity: "critical", impact: BACKUP, test: (_, t) => SQL.test(t) },
  { path: "database.sql", what: "database dump", severity: "critical", impact: BACKUP, test: (_, t) => SQL.test(t) },
  { path: "actuator/env", what: "Spring Boot actuator /env endpoint", severity: "critical", impact: "Dumps the application's configuration and environment, often including credentials.", test: (_, t) => /"(propertySources|activeProfiles)"/.test(t) },
  { path: "server-status", what: "Apache server-status page", severity: "medium", html: true, impact: "Shows live requests, client IPs and internal URLs.", test: (_, t) => /Apache Server Status/i.test(t) },
  { path: "phpinfo.php", what: "phpinfo() page", severity: "medium", html: true, impact: "Reveals server paths, versions, modules and environment variables.", test: (_, t) => /phpinfo\(\)/.test(t) && /PHP Version/.test(t) },
  { path: "info.php", what: "phpinfo() page", severity: "medium", html: true, impact: "Reveals server paths, versions, modules and environment variables.", test: (_, t) => /phpinfo\(\)/.test(t) && /PHP Version/.test(t) },
  { path: "swagger.json", what: "API description (Swagger)", severity: "low", impact: "Maps every API endpoint. Fine if the API is public; otherwise it guides attackers.", test: (_, t) => OPENAPI.test(t) },
  { path: "openapi.json", what: "API description (OpenAPI)", severity: "low", impact: "Maps every API endpoint. Fine if the API is public; otherwise it guides attackers.", test: (_, t) => OPENAPI.test(t) },
  { path: "v3/api-docs", what: "API description (springdoc)", severity: "low", impact: "Maps every API endpoint. Fine if the API is public; otherwise it guides attackers.", test: (_, t) => OPENAPI.test(t) },
];

export interface ExposedFile {
  path: string;
  what: string;
  severity: Severity;
  impact: string;
}

interface Fetched {
  status: number;
  contentType: string;
  body: Buffer;
}

/** Read at most `max` bytes of a response body, then cancel the rest of the download. */
export async function readCapped(res: Response, max = MAX_BYTES): Promise<Buffer> {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    while (size < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
      size += value.byteLength;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).subarray(0, max);
}

async function getSameOrigin(url: string, domain: string): Promise<Response | null> {
  let current = new URL(url);
  for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt += 1) {
    if (current.host !== domain) return null;
    const response = await fetchWithTimeout(current.toString(), { timeoutMs: REQUEST_TIMEOUT_MS });
    if (response.status < 300 || response.status >= 400) return response;
    response.body?.cancel().catch(() => {});
    const location = response.headers.get("location");
    if (!location) return null;
    const next = new URL(location, current);
    if (next.host !== domain) return null;
    current = next;
  }
  return null;
}

async function fetchPath(domain: string, path: string): Promise<Fetched | null> {
  try {
    const res = await getSameOrigin(`${targetOrigin(domain)}/${path}`, domain);
    if (!res) return null;
    return { status: res.status, contentType: res.headers.get("content-type") ?? "", body: await readCapped(res) };
  } catch {
    return null;
  }
}

const looksHtml = (f: Fetched) => /text\/html/i.test(f.contentType) || /^\s*<(!doctype|html)/i.test(f.body.subarray(0, 200).toString("utf8"));

/** Same page as the catch-all response? (Identical, or HTML of nearly the same length.) */
function likeBaseline(f: Fetched, baseline: Fetched | null): boolean {
  if (!baseline) return false;
  if (f.body.equals(baseline.body)) return true;
  const a = f.body.length, b = baseline.body.length;
  return looksHtml(f) && looksHtml(baseline) && Math.abs(a - b) <= Math.max(64, b * 0.05);
}

/** Pure decision for one probe response (exported for tests). */
export function matchProbe(probe: Probe, f: Fetched | null, baseline: Fetched | null): boolean {
  if (!f || f.status !== 200 || f.body.length === 0) return false;
  if (!probe.html && looksHtml(f)) return false;
  if (likeBaseline(f, baseline)) return false;
  return probe.test(f.body, f.body.toString("utf8"));
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    })
  );
  return out;
}

/** Same-origin script URLs from the home page, for source map probing. */
export function scriptPaths(html: string, domain: string): string[] {
  const origin = targetOrigin(domain);
  const paths = new Set<string>();
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+\.js)(\?[^"']*)?["']/gi)) {
    try {
      const u = new URL(m[1], `${origin}/`);
      if (u.host === domain) paths.add(u.pathname.replace(/^\//, ""));
    } catch {
      // ignore malformed src
    }
    if (paths.size >= 5) break;
  }
  return [...paths];
}

async function findSourceMaps(domain: string, home: Fetched | null, baseline: Fetched | null): Promise<ExposedFile[]> {
  if (!home || home.status !== 200) return [];
  const scripts = scriptPaths(home.body.toString("utf8"), domain);
  const maps = await mapLimit(scripts, CONCURRENCY, async (js) => {
    const f = await fetchPath(domain, `${js}.map`);
    if (!f || f.status !== 200 || looksHtml(f) || likeBaseline(f, baseline)) return null;
    const text = f.body.toString("utf8");
    if (!/"mappings"\s*:/.test(text) || !/"sources"\s*:/.test(text)) return null;
    const withSource = /"sourcesContent"\s*:/.test(text);
    return {
      path: `${js}.map`,
      what: withSource ? "JavaScript source map with original source" : "JavaScript source map",
      severity: (withSource ? "medium" : "low") as Severity,
      impact: withSource
        ? "Ships the original, unminified front-end source, including comments and internal API routes."
        : "Reveals the original file structure and names of the front-end code.",
    };
  });
  return maps.filter((m): m is ExposedFile => m !== null);
}

export function exposedFilesAdapter(domain: string, exposed: ExposedFile[], catchAll = false): DomainResult {
  const G = "Exposed files";
  const origin = targetOrigin(domain);
  const findings: Finding[] = exposed.map((e) => ({
    skill: "exposed-sensitive-file",
    category: "domain",
    finding_id: makeFindingId({ domain, check: `exposed-file-${e.path}`, rule_id: "exposed-sensitive-file" }),
    rule_id: "exposed-sensitive-file",
    severity: e.severity,
    confidence: "high",
    title: `Exposed ${e.what}: /${e.path}`,
    location: { url: `${origin}/${e.path}` },
    raw_snippet: null,
    tool_message: `/${e.path} is publicly readable and its content matches a ${e.what}. ${e.impact}`,
    metadata: { owasp: "A05:2021-Security Misconfiguration", file: e.path },
  }));

  const checks: CheckResult[] = exposed.map((e) => ({
    group: G,
    name: `/${e.path}`,
    result: "finding",
    severity: e.severity,
    observed: `HTTP 200 with ${e.what} content`,
    remediation: /\.map$/.test(e.path)
      ? "Don't deploy .map files (or upload them only to your error tracker)."
      : "Remove it from the web root and deny the path at the web server; rotate any secrets it contained.",
    source: "exposed-sensitive-file",
  }));
  if (exposed.length === 0) {
    checks.push({
      group: G,
      name: `${PROBES.length} common paths + source maps`,
      result: "pass",
      observed: catchAll
        ? "None exposed (the site answers 200 for any path; matched on file contents only)"
        : "None exposed",
      source: "exposed-sensitive-file",
    });
  }
  return { findings, checks };
}

export async function runExposedFiles(domain: string): Promise<DomainResult> {
  const [baselineRaw, home] = await Promise.all([
    fetchPath(domain, `scanner-x-${randomBytes(6).toString("hex")}.txt`),
    fetchPath(domain, ""),
  ]);
  const baseline = baselineRaw && baselineRaw.status === 200 ? baselineRaw : null;

  const [probed, maps] = await Promise.all([
    mapLimit(PROBES, CONCURRENCY, async (p) => (matchProbe(p, await fetchPath(domain, p.path), baseline) ? p : null)),
    findSourceMaps(domain, home, baseline),
  ]);
  const exposed: ExposedFile[] = [
    ...probed.filter((p): p is Probe => p !== null).map(({ path, what, severity, impact }) => ({ path, what, severity, impact })),
    ...maps,
  ];
  return exposedFilesAdapter(domain, exposed, baseline !== null);
}
