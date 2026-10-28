import { CheckResult, Finding, makeFindingId } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { findTakeovers, takeoverAdapter } from "./takeover";
import { fetchWithTimeout, netError } from "./util";

/**
 * Subdomain enumeration via certificate transparency logs (crt.sh), then a takeover check:
 * DNS lookups for every subdomain, and one GET to those whose CNAME points at a known
 * hosting service (to read its "nothing here" page).
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
  const unavailable = (why: string): DomainResult => ({
    findings: [],
    checks: [{ group: "Subdomains", name: "CT enumeration", result: "inconclusive", observed: why, source: "subdomains" }],
    notes: [`Subdomains: certificate transparency lookup failed (${why}), so subdomains and takeovers were not checked.`],
  });
  let names: string[];
  try {
    const res = await fetchWithTimeout(
      `https://crt.sh/?q=${encodeURIComponent(`%.${host}`)}&output=json`,
      { timeoutMs: 30000, publicFeed: true }
    );
    if (!res.ok) return unavailable(`crt.sh returned HTTP ${res.status}`);
    const entries = (await res.json()) as CrtShEntry[];
    const set = new Set<string>();
    for (const e of entries) {
      for (const v of (e.name_value ?? e.common_name ?? "").split("\n")) {
        const name = v.trim().toLowerCase();
        if (name && !name.startsWith("*.") && name.endsWith(`.${host}`)) set.add(name);
      }
    }
    names = [...set].sort();
  } catch (err) {
    return unavailable(netError(err));
  }

  const listing = subdomainAdapter(host, names);
  if (names.length === 0) return listing;
  const { results, checked } = await findTakeovers(names);
  const takeover = takeoverAdapter(host, results, checked, names.length);
  return { findings: [...takeover.findings, ...listing.findings], checks: [...listing.checks, ...takeover.checks] };
}
