import { CheckResult, Finding, makeFindingId } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout } from "./util";
import type { Response } from "undici";

const PATHS = [".git/config", ".git/HEAD", ".env", ".env.local", ".env.production"];
const MAX_REDIRECTS = 3;
const REQUEST_TIMEOUT_MS = 4000;

interface ExposedFile {
  path: string;
  body: string;
}

function isRecognizable(path: string, body: string): boolean {
  if (path === ".git/config") {
    return /\[core\]|\[remote\b/i.test(body);
  }
  if (path === ".git/HEAD") {
    return /^\s*ref:\s*\S+/m.test(body) || /^\s*[0-9a-f]{40}\s*$/im.test(body);
  }
  return /^[A-Z_]+=.+$/m.test(body);
}

async function getSameOrigin(url: string, domain: string): Promise<Response | null> {
  let current = new URL(url);
  for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt += 1) {
    if (current.hostname !== domain) return null;
    const response = await fetchWithTimeout(current.toString(), {
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) return null;
    const next = new URL(location, current);
    if (next.hostname !== domain) return null;
    current = next;
  }
  return null;
}

async function fetchCandidate(domain: string, path: string): Promise<ExposedFile | null> {
  try {
    const response = await getSameOrigin(`https://${domain}/${path}`, domain);
    if (!response || response.status !== 200) return null;
    const body = await response.text();
    return isRecognizable(path, body) ? { path, body } : null;
  } catch {
    return null;
  }
}

export function exposedFilesAdapter(
  domain: string,
  exposed: ExposedFile[]
): DomainResult {
  const findings: Finding[] = exposed.map(({ path }) => ({
    skill: "exposed-sensitive-file",
    category: "domain",
    finding_id: makeFindingId({
      domain,
      check: `exposed-file-${path}`,
      rule_id: "exposed-sensitive-file",
    }),
    rule_id: "exposed-sensitive-file",
    severity: "critical",
    confidence: "high",
    title: `Exposed ${path} at web root`,
    location: { url: `https://${domain}/${path}` },
    raw_snippet: null,
    tool_message: "Sensitive file publicly accessible and returned recognizable content",
    metadata: { file: path },
  }));

  if (findings.length > 0) {
    return {
      findings,
      checks: exposed.map(({ path }) => ({
        group: "Exposed files",
        name: path,
        result: "finding",
        severity: "critical",
        observed: `HTTP 200 with recognizable ${path} content`,
        remediation: "Remove the file from the web root and block access at the origin/web server.",
        source: "exposed-sensitive-file",
      })),
    };
  }

  const pass: CheckResult = {
    group: "Exposed files",
    name: "Common sensitive paths",
    result: "pass",
    observed: "No exposed .git or .env files found at common paths",
    source: "exposed-sensitive-file",
  };
  return { findings: [], checks: [pass] };
}

export async function runExposedFiles(domain: string): Promise<DomainResult> {
  const exposed = (await Promise.all(PATHS.map((path) => fetchCandidate(domain, path)))).filter(
    (value): value is ExposedFile => value !== null
  );
  return exposedFilesAdapter(domain, exposed);
}
