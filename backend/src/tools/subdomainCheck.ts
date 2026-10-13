import { CheckResult, Finding, makeFindingId } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout } from "./util";

/**
 * Subdomain enumeration via certificate transparency logs (domain mode, passive).
 * Queries the public crt.sh API — no active probing of the discovered hosts.
 */

interface CrtShEntry {
  name_value?: string;
  common_name?: string;
}

export function subdomainAdapter(host: string, subdomains: string[]): DomainResult {
  const G = "Subdomains";
  if (subdomains.length === 0) {
    return {
      findings: [],
      checks: [
        { group: G, name: "CT enumeration", result: "pass", observed: "no subdomains in CT logs", source: "subdomains" },
      ],
    };
  }
  const url = host;
  const sensitive = subdomains.filter((s) =>
    /(^|\.)(dev|staging|stage|test|internal|admin|vpn|jenkins|jira|git|db|api-internal)\./.test(
      `.${s}`
    )
  );
  const severity = sensitive.length > 0 ? "medium" : "low";
  const finding: Finding = {
    skill: "subdomain-ct-enumeration",
    category: "domain",
    finding_id: makeFindingId({
      domain: host,
      check: "ct-subdomains",
      rule_id: "ct-subdomains",
    }),
    rule_id: "ct-subdomains",
    severity,
    confidence: "medium",
    title: `${subdomains.length} subdomains exposed via certificate transparency`,
    location: { url },
    raw_snippet: null,
    tool_message:
      sensitive.length > 0
        ? `Certificate transparency logs reveal ${subdomains.length} subdomains, including potentially sensitive hosts: ${sensitive
            .slice(0, 10)
            .join(", ")}.`
        : `Certificate transparency logs reveal ${subdomains.length} subdomains for this domain.`,
    metadata: {
      owasp: "A05:2021-Security Misconfiguration",
      count: subdomains.length,
      subdomains: subdomains.slice(0, 100),
      sensitive,
    },
  };
  return {
    findings: [finding],
    checks: [
      {
        group: G,
        name: "CT enumeration",
        result: "finding",
        severity,
        observed:
          sensitive.length > 0
            ? `${subdomains.length} found, incl. ${sensitive.slice(0, 3).join(", ")}`
            : `${subdomains.length} subdomains found`,
        remediation: "Review exposed hosts; retire or firewall non-public ones.",
        source: "subdomains",
      },
    ],
  };
}

export async function runSubdomainCheck(host: string): Promise<DomainResult> {
  try {
    const res = await fetchWithTimeout(
      `https://crt.sh/?q=${encodeURIComponent(`%.${host}`)}&output=json`,
      { timeoutMs: 15000 }
    );
    if (!res.ok) return { findings: [], checks: [] };
    const entries = (await res.json()) as CrtShEntry[];
    const names = new Set<string>();
    for (const e of entries) {
      const values = (e.name_value ?? e.common_name ?? "").split("\n");
      for (const v of values) {
        const name = v.trim().toLowerCase();
        if (name && !name.startsWith("*.") && name.endsWith(host)) {
          names.add(name);
        }
      }
    }
    names.delete(host);
    return subdomainAdapter(host, [...names].sort());
  } catch {
    return { findings: [], checks: [] };
  }
}
