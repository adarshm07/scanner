import { CheckResult, Finding, makeFindingId, Severity } from "../schema/finding";
import { DomainResult } from "./domainResult";
import type { FixInput } from "./fixConfig";
import { fetchWithTimeout, isLocalTarget, targetOrigin } from "./util";

/**
 * HTTP security headers, cookies, CORS and HTTPS enforcement (domain mode).
 * Requests: GET / (headers, cookies), GET / with an untrusted Origin (CORS),
 * GET http:// (redirect to HTTPS), and the public HSTS preload list status.
 */

interface HeaderCheckDef {
  header: string;
  check: string;
  severity: Severity;
  title: string;
  message: string;
}

const OWASP = "A05:2021-Security Misconfiguration";

const REQUIRED_HEADERS: HeaderCheckDef[] = [
  {
    header: "strict-transport-security",
    check: "missing-hsts",
    severity: "medium",
    title: "Missing Strict-Transport-Security header",
    message: "No HSTS header found. HSTS forces HTTPS and prevents protocol downgrade.",
  },
  {
    header: "x-frame-options",
    check: "missing-x-frame-options",
    severity: "low",
    title: "Missing X-Frame-Options header",
    message: "No X-Frame-Options header found. Site may be vulnerable to clickjacking.",
  },
  {
    header: "x-content-type-options",
    check: "missing-x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options header",
    message: "No X-Content-Type-Options: nosniff header found. Browsers may MIME-sniff responses.",
  },
  {
    header: "referrer-policy",
    check: "missing-referrer-policy",
    severity: "low",
    title: "Missing Referrer-Policy header",
    message: "No Referrer-Policy header found. Referrer data may leak to third parties.",
  },
  {
    header: "permissions-policy",
    check: "missing-permissions-policy",
    severity: "low",
    title: "Missing Permissions-Policy header",
    message:
      "No Permissions-Policy header found. Any script on the page (including third-party ones) can ask for the camera, microphone or location.",
  },
];

/** Untrusted origin sent in the CORS probe. `.invalid` can never be a real site. */
export const PROBE_ORIGIN = "https://scanner-x-cors-check.invalid";
const ONE_YEAR = 31536000;
const MIN_HSTS = 15552000; // 180 days
const SESSION_COOKIE = /sess|sid|token|auth|jwt|login|remember/i;

export interface HeaderData {
  headers: Record<string, string>;
  setCookies: string[];
  /** Response headers when GET / was sent with Origin: PROBE_ORIGIN (null if it failed). */
  cors: { allowOrigin: string | null; allowCredentials: boolean } | null;
  /** What plain http:// does: "redirect-https", "served", "other" or "unavailable". Null = not tested. */
  http: { result: "redirect-https" | "served" | "other" | "unavailable"; location?: string; status?: number } | null;
  /** hstspreload.org status ("preloaded", "pending", "unknown", ...), or null if not checked. */
  preload: string | null;
}

interface Cookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

export function parseSetCookie(raw: string): Cookie {
  const [pair, ...attrs] = raw.split(";");
  const name = pair.split("=")[0].trim();
  const lower = attrs.map((a) => a.trim().toLowerCase());
  const same = lower.find((a) => a.startsWith("samesite="));
  return {
    name,
    secure: lower.includes("secure"),
    httpOnly: lower.includes("httponly"),
    sameSite: same ? same.slice("samesite=".length) : null,
  };
}

function hstsMaxAge(value: string): number | null {
  const m = /max-age\s*=\s*"?(\d+)/i.exec(value);
  return m ? Number(m[1]) : null;
}

export function headerAdapter(host: string, data: HeaderData): DomainResult & { fix: FixInput } {
  const { headers } = data;
  const url = targetOrigin(host);
  const https = url.startsWith("https:");
  const G = "HTTP headers";
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const fix: FixInput = {
    server: headers["server"] ?? null,
    poweredBy: headers["x-powered-by"] ?? null,
    platformHints: Object.keys(headers).filter((h) => /^(x-vercel-id|x-nf-request-id|cf-ray|x-amz-cf-id|x-azure-ref)$/.test(h)),
    missingHeaders: [],
    weakHsts: false,
    hideServerVersion: false,
    hidePoweredBy: false,
    httpRedirect: false,
    cookies: [],
    csp: !("content-security-policy" in headers),
  };

  const add = (
    check: string,
    severity: Severity,
    title: string,
    message: string,
    row: { name: string; observed: string; remediation: string },
    metadata: Record<string, unknown> = {},
    confidence: Finding["confidence"] = "high"
  ) => {
    findings.push({
      skill: `header-${check}`,
      category: "domain",
      finding_id: makeFindingId({ domain: host, check, rule_id: check }),
      rule_id: check,
      severity,
      confidence,
      title,
      location: { url },
      raw_snippet: null,
      tool_message: message,
      metadata: { owasp: OWASP, ...metadata },
    });
    checks.push({ group: G, result: "finding", severity, source: "headers", ...row });
  };
  const pass = (name: string, observed: string) => checks.push({ group: G, name, result: "pass", observed, source: "headers" });

  // Required headers
  for (const def of REQUIRED_HEADERS) {
    if (def.header in headers) {
      pass(def.header, headers[def.header].slice(0, 80));
      continue;
    }
    fix.missingHeaders.push(def.header);
    add(def.check, def.severity, def.title, def.message, { name: def.header, observed: "absent on GET /", remediation: def.message }, { header: def.header });
  }

  // HSTS strength + preload
  const hsts = headers["strict-transport-security"];
  if (hsts) {
    const maxAge = hstsMaxAge(hsts);
    if (maxAge === null || maxAge < MIN_HSTS) {
      fix.weakHsts = true;
      add(
        "weak-hsts",
        "low",
        "HSTS max-age is too short",
        `Strict-Transport-Security max-age is ${maxAge ?? "missing"} seconds. Browsers forget the HTTPS-only rule quickly; use at least 180 days (1 year recommended).`,
        { name: "HSTS max-age", observed: `${maxAge ?? "missing"}s`, remediation: "Set max-age=31536000 (1 year)." },
        { header: "strict-transport-security" }
      );
    }
    const eligible = (maxAge ?? 0) >= ONE_YEAR && /includesubdomains/i.test(hsts) && /preload/i.test(hsts);
    const status = data.preload;
    checks.push({
      group: G,
      name: "HSTS preload",
      result: "pass",
      observed:
        status === "preloaded"
          ? "on the browser preload list"
          : status === "pending"
            ? "submitted, pending inclusion"
            : eligible
              ? "header is preload-ready; not on the list yet (submit at hstspreload.org)"
              : "not on the preload list (optional: needs max-age ≥ 1 year, includeSubDomains, preload)",
      source: "headers",
    });
  }

  // HTTP -> HTTPS
  if (data.http) {
    const h = data.http;
    if (h.result === "served") {
      fix.httpRedirect = true;
      add(
        "no-https-redirect",
        "medium",
        "Plain HTTP is served without redirecting to HTTPS",
        `http://${host}/ answered HTTP ${h.status ?? 200} instead of redirecting to https://. Visitors who type the bare domain, and links using http://, stay on an unencrypted connection.`,
        { name: "HTTP → HTTPS", observed: `http:// answered ${h.status ?? 200}`, remediation: "Redirect every http:// request to https:// with a 301." }
      );
    } else if (h.result === "other") {
      fix.httpRedirect = true;
      add(
        "no-https-redirect",
        "low",
        "HTTP redirects somewhere other than HTTPS",
        `http://${host}/ redirects to ${h.location ?? "an unexpected location"} instead of an https:// URL.`,
        { name: "HTTP → HTTPS", observed: `→ ${h.location ?? `HTTP ${h.status}`}`, remediation: "Redirect http:// to the same URL on https://." }
      );
    } else {
      pass("HTTP → HTTPS", h.result === "redirect-https" ? `redirects to ${h.location}` : "port 80 not served");
    }
  }

  // Version disclosure
  const server = headers["server"];
  if (server && /\d/.test(server)) {
    fix.hideServerVersion = true;
    add(
      "server-version-disclosure",
      "low",
      "Server header discloses version information",
      `Server header "${server}" reveals software/version details.`,
      { name: "server", observed: `Server: ${server}`, remediation: "Suppress the version in the Server header." },
      { server },
      "medium"
    );
  } else if (server) {
    pass("server", `Server: ${server}`);
  }
  const poweredBy = headers["x-powered-by"];
  if (poweredBy) {
    fix.hidePoweredBy = true;
    add(
      "x-powered-by-disclosure",
      "low",
      "X-Powered-By header reveals the framework",
      `X-Powered-By: ${poweredBy} tells attackers which framework (and often version) to target.`,
      { name: "x-powered-by", observed: poweredBy.slice(0, 80), remediation: "Remove the X-Powered-By header." },
      { poweredBy },
      "medium"
    );
  }

  // Cookies
  const cookies = data.setCookies.map(parseSetCookie).filter((c) => c.name);
  for (const c of cookies) {
    const session = SESSION_COOKIE.test(c.name);
    const issues: string[] = [];
    let severity: Severity = "low";
    if (https && !c.secure) {
      issues.push("Secure");
      if (session) severity = "medium";
    }
    if (session && !c.httpOnly) {
      issues.push("HttpOnly");
      severity = "medium";
    }
    if (session && !c.sameSite) issues.push("SameSite");
    if (c.sameSite === "none" && !c.secure && !issues.includes("Secure")) issues.push("Secure (required with SameSite=None)");
    if (issues.length === 0) continue;
    fix.cookies.push(c.name);
    add(
      `cookie-flags-${c.name}`,
      severity,
      `Cookie "${c.name}" is missing ${issues.join(", ")}`,
      [
        `Set-Cookie for "${c.name}"${session ? " (looks like a session or auth cookie)" : ""} lacks ${issues.join(", ")}.`,
        issues.some((i) => i.startsWith("Secure")) ? "Without Secure it is also sent over plain HTTP." : "",
        issues.includes("HttpOnly") ? "Without HttpOnly any XSS can read it." : "",
        issues.includes("SameSite") ? "Without SameSite it relies on the browser default for cross-site requests." : "",
      ].filter(Boolean).join(" "),
      { name: `cookie ${c.name}`, observed: `missing ${issues.join(", ")}`, remediation: `Set ${issues.join(", ")} on the "${c.name}" cookie.` },
      { cookie: c.name }
    );
  }
  if (cookies.length && !fix.cookies.length) pass("cookies", `${cookies.length} set on /, flags OK`);
  if (!cookies.length) pass("cookies", "none set on / (cookies set after login aren't checked)");

  // CORS
  if (data.cors) {
    const { allowOrigin, allowCredentials } = data.cors;
    if (allowOrigin === PROBE_ORIGIN && allowCredentials) {
      add(
        "cors-reflects-origin-credentials",
        "high",
        "CORS trusts any website, with credentials",
        `GET / with Origin: ${PROBE_ORIGIN} returned Access-Control-Allow-Origin: ${PROBE_ORIGIN} and Access-Control-Allow-Credentials: true. Any website a logged-in user visits can read responses from this site as that user.`,
        { name: "CORS", observed: "reflects any Origin + credentials", remediation: "Only echo origins from an explicit allowlist." },
        { cwe: "CWE-942" }
      );
    } else if (allowOrigin === PROBE_ORIGIN) {
      add(
        "cors-reflects-origin",
        "low",
        "CORS reflects any origin",
        `GET / with Origin: ${PROBE_ORIGIN} was echoed back in Access-Control-Allow-Origin (without credentials). Harmless for public content, risky if any response depends on the caller's network or IP.`,
        { name: "CORS", observed: "reflects any Origin (no credentials)", remediation: "Only echo origins from an explicit allowlist." },
        { cwe: "CWE-942" },
        "medium"
      );
    } else {
      pass("CORS", allowOrigin ? `Access-Control-Allow-Origin: ${allowOrigin.slice(0, 60)}` : "untrusted Origin not allowed on /");
    }
  }

  return { findings, checks, fix };
}

async function probeHttp(host: string): Promise<HeaderData["http"]> {
  if (isLocalTarget(host)) return null; // local fixtures are plain http by design
  try {
    const res = await fetchWithTimeout(`http://${host}/`, { timeoutMs: 6000 });
    res.body?.cancel().catch(() => {});
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location") ?? "";
      let https = false;
      try {
        https = new URL(location, `http://${host}/`).protocol === "https:";
      } catch {
        // malformed Location
      }
      return { result: https ? "redirect-https" : "other", location, status: res.status };
    }
    return { result: "served", status: res.status };
  } catch {
    return { result: "unavailable" };
  }
}

async function probeCors(host: string): Promise<HeaderData["cors"]> {
  try {
    const res = await fetchWithTimeout(targetOrigin(host), { timeoutMs: 8000, headers: { Origin: PROBE_ORIGIN } });
    res.body?.cancel().catch(() => {});
    return {
      allowOrigin: res.headers.get("access-control-allow-origin"),
      allowCredentials: /^true$/i.test(res.headers.get("access-control-allow-credentials") ?? ""),
    };
  } catch {
    return null;
  }
}

async function preloadStatus(host: string, hsts: string | undefined): Promise<string | null> {
  if (!hsts || isLocalTarget(host)) return null;
  try {
    const res = await fetchWithTimeout(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(host)}`, { timeoutMs: 5000 });
    if (!res.ok) return null;
    const body = (await res.json()) as { status?: string };
    return typeof body.status === "string" ? body.status : null;
  } catch {
    return null;
  }
}

export async function runHeaderCheck(host: string): Promise<DomainResult> {
  try {
    const [res, cors, http] = await Promise.all([
      fetchWithTimeout(targetOrigin(host), { timeoutMs: 12000 }),
      probeCors(host),
      probeHttp(host),
    ]);
    res.body?.cancel().catch(() => {});
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => (headers[key.toLowerCase()] = value));
    const preload = await preloadStatus(host, headers["strict-transport-security"]);
    return headerAdapter(host, { headers, setCookies: res.headers.getSetCookie(), cors, http, preload });
  } catch (err) {
    return {
      findings: [
        {
          skill: "header-fetch-failed",
          category: "domain",
          finding_id: makeFindingId({ domain: host, check: "header-fetch-failed", rule_id: "header-fetch-failed" }),
          rule_id: "header-fetch-failed",
          severity: "low",
          confidence: "low",
          title: "Could not fetch HTTP headers",
          location: { url: targetOrigin(host) },
          raw_snippet: null,
          tool_message: `Header inspection failed: ${(err as Error).message}`,
          metadata: {},
        },
      ],
      checks: [
        {
          group: "HTTP headers",
          name: "fetch",
          result: "finding",
          severity: "low",
          observed: `failed: ${(err as Error).message}`,
          source: "headers",
        },
      ],
    };
  }
}
