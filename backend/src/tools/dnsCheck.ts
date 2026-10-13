import { promises as dns } from "dns";
import { CheckResult, Finding, makeFindingId } from "../schema/finding";
import { DomainResult } from "./domainResult";

/**
 * DNS email-authentication check (domain mode, passive). Verifies presence of
 * SPF, DMARC, and (best-effort) DKIM TXT records via public DNS resolution.
 */

async function resolveTxt(name: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(name);
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

interface DnsInfo {
  hasSpf: boolean;
  spfRecord: string | null;
  hasDmarc: boolean;
  dmarcPolicy: string | null;
  hasDkim: boolean;
}

export function dnsAdapter(host: string, info: DnsInfo): DomainResult {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const G = "Email auth (DNS)";

  const finding = (
    check: string,
    name: string,
    title: string,
    message: string,
    observed: string,
    remediation: string,
    severity: Finding["severity"] = "medium"
  ) => {
    findings.push({
      skill: `dns-${check}`,
      category: "domain",
      finding_id: makeFindingId({ domain: host, check, rule_id: check }),
      rule_id: check,
      severity,
      confidence: "high",
      title,
      location: { url: host },
      raw_snippet: null,
      tool_message: message,
      metadata: { owasp: "A05:2021-Security Misconfiguration", control: check },
    });
    checks.push({ group: G, name, result: "finding", severity, observed, remediation, source: "dns" });
  };
  const pass = (name: string, observed: string) =>
    checks.push({ group: G, name, result: "pass", observed, source: "dns" });

  if (!info.hasSpf) {
    finding(
      "missing-spf",
      "SPF",
      "No SPF record found",
      "Domain has no SPF (v=spf1) TXT record; email spoofing protection is weakened.",
      "no v=spf1 record",
      "Publish an SPF TXT record listing authorized senders."
    );
  } else {
    pass("SPF", info.spfRecord ?? "v=spf1 present");
  }

  if (!info.hasDmarc) {
    finding(
      "missing-dmarc",
      "DMARC",
      "No DMARC record found",
      "Domain has no _dmarc TXT record; spoofed mail cannot be reliably rejected.",
      "no _dmarc record",
      "Publish a _dmarc TXT record with p=quarantine or p=reject."
    );
  } else if (info.dmarcPolicy === "none") {
    finding(
      "dmarc-policy-none",
      "DMARC",
      "DMARC policy is p=none",
      "DMARC is present but set to p=none, which only monitors and does not block spoofing.",
      "p=none (monitor only)",
      "Move to p=quarantine or p=reject after monitoring.",
      "low"
    );
  } else {
    pass("DMARC", `p=${info.dmarcPolicy}`);
  }

  if (!info.hasDkim) {
    finding(
      "dkim-not-detected",
      "DKIM",
      "DKIM not detected on common selectors",
      "No DKIM record found on common selectors (default, google, selector1). Verify DKIM is configured.",
      "not found on common selectors",
      "Confirm DKIM signing is configured for your mail provider.",
      "low"
    );
  } else {
    pass("DKIM", "v=DKIM1 present");
  }

  return { findings, checks };
}

export async function runDnsCheck(host: string): Promise<DomainResult> {
  const [rootTxt, dmarcTxt] = await Promise.all([
    resolveTxt(host),
    resolveTxt(`_dmarc.${host}`),
  ]);

  const spfRecord = rootTxt.find((r) => /v=spf1/i.test(r)) ?? null;
  const hasSpf = Boolean(spfRecord);
  const dmarcRecord = dmarcTxt.find((r) => /v=DMARC1/i.test(r));
  const hasDmarc = Boolean(dmarcRecord);
  const policyMatch = dmarcRecord?.match(/p=([a-z]+)/i);
  const dmarcPolicy = policyMatch ? policyMatch[1].toLowerCase() : null;

  const commonSelectors = ["default", "google", "selector1"];
  const dkimResults = await Promise.all(
    commonSelectors.map((s) => resolveTxt(`${s}._domainkey.${host}`))
  );
  const hasDkim = dkimResults.some((r) => r.some((v) => /v=DKIM1|k=rsa/i.test(v)));

  return dnsAdapter(host, { hasSpf, spfRecord, hasDmarc, dmarcPolicy, hasDkim });
}
