import { CheckResult, Finding, makeFindingId, Severity } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout, targetOrigin } from "./util";

/**
 * HTTP security header inspection (domain mode, passive). Fetches the root URL
 * and checks for the presence/quality of key security headers.
 */

interface HeaderCheckDef {
  header: string;
  check: string;
  severity: Severity;
  title: string;
  message: string;
  owasp?: string;
}

const REQUIRED_HEADERS: HeaderCheckDef[] = [
  {
    header: "strict-transport-security",
    check: "missing-hsts",
    severity: "medium",
    title: "Missing Strict-Transport-Security header",
    message:
      "No HSTS header found. HSTS forces HTTPS and prevents protocol downgrade.",
    owasp: "A05:2021-Security Misconfiguration",
  },
  {
    header: "x-frame-options",
    check: "missing-x-frame-options",
    severity: "low",
    title: "Missing X-Frame-Options header",
    message: "No X-Frame-Options header found. Site may be vulnerable to clickjacking.",
    owasp: "A05:2021-Security Misconfiguration",
  },
  {
    header: "x-content-type-options",
    check: "missing-x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options header",
    message:
      "No X-Content-Type-Options: nosniff header found. Browsers may MIME-sniff responses.",
    owasp: "A05:2021-Security Misconfiguration",
  },
  {
    header: "referrer-policy",
    check: "missing-referrer-policy",
    severity: "low",
    title: "Missing Referrer-Policy header",
    message: "No Referrer-Policy header found. Referrer data may leak to third parties.",
    owasp: "A05:2021-Security Misconfiguration",
  },
];

export function headerAdapter(
  host: string,
  headers: Record<string, string>,
  serverHeader: string | null
): DomainResult {
  const url = targetOrigin(host);
  const G = "HTTP headers";
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];

  for (const def of REQUIRED_HEADERS) {
    const present = def.header in headers;
    if (present) {
      checks.push({
        group: G,
        name: def.header,
        result: "pass",
        observed: headers[def.header].slice(0, 80),
        source: "headers",
      });
    } else {
      findings.push({
        skill: `header-${def.check}`,
        category: "domain",
        finding_id: makeFindingId({ domain: host, check: def.check, rule_id: def.check }),
        rule_id: def.check,
        severity: def.severity,
        confidence: "high",
        title: def.title,
        location: { url },
        raw_snippet: null,
        tool_message: def.message,
        metadata: { owasp: def.owasp, header: def.header },
      });
      checks.push({
        group: G,
        name: def.header,
        result: "finding",
        severity: def.severity,
        observed: "absent on GET /",
        remediation: def.message,
        source: "headers",
      });
    }
  }

  // Verbose Server header can leak version info.
  if (serverHeader && /\d/.test(serverHeader)) {
    findings.push({
      skill: "header-server-version-disclosure",
      category: "domain",
      finding_id: makeFindingId({
        domain: host,
        check: "server-version-disclosure",
        rule_id: "server-version-disclosure",
      }),
      rule_id: "server-version-disclosure",
      severity: "low",
      confidence: "medium",
      title: "Server header discloses version information",
      location: { url },
      raw_snippet: null,
      tool_message: `Server header "${serverHeader}" reveals software/version details.`,
      metadata: {
        owasp: "A05:2021-Security Misconfiguration",
        server: serverHeader,
      },
    });
    checks.push({
      group: G,
      name: "server",
      result: "finding",
      severity: "low",
      observed: `Server: ${serverHeader}`,
      remediation: "Suppress the version in the Server header.",
      source: "headers",
    });
  } else if (serverHeader) {
    checks.push({ group: G, name: "server", result: "pass", observed: `Server: ${serverHeader}`, source: "headers" });
  }

  return { findings, checks };
}

export async function runHeaderCheck(host: string): Promise<DomainResult> {
  try {
    const res = await fetchWithTimeout(targetOrigin(host), { timeoutMs: 12000 });
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => (headers[key.toLowerCase()] = value));
    return headerAdapter(host, headers, headers["server"] ?? null);
  } catch (err) {
    return {
      findings: [
        {
          skill: "header-fetch-failed",
          category: "domain",
          finding_id: makeFindingId({
            domain: host,
            check: "header-fetch-failed",
            rule_id: "header-fetch-failed",
          }),
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
