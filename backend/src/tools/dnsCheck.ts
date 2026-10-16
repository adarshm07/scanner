import { promises as dns } from "dns";
import { CheckResult, Finding, makeFindingId } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout, isLocalTarget } from "./util";

/**
 * DNS security (domain mode, passive): email authentication (SPF, DMARC, best-effort DKIM,
 * MTA-STS), CAA (which CAs may issue certificates) and DNSSEC. Public DNS lookups, one
 * DNS-over-HTTPS query for DNSSEC validation, and the MTA-STS policy file if one is published.
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
  /** Mail exchangers; MTA-STS only matters when the domain receives mail. */
  hasMx?: boolean;
  /** MTA-STS policy mode ("enforce", "testing", "none"), "missing", or "broken" (TXT without a policy file). */
  mtaSts?: "enforce" | "testing" | "none" | "missing" | "broken";
  /** CAA issuers and the name they were found on; null = no CAA anywhere up the tree. */
  caa?: { name: string; issuers: string[] } | null;
  /** DNSSEC: true = validated, false = not signed, null = couldn't tell. */
  dnssec?: boolean | null;
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
    severity: Finding["severity"] = "medium",
    group = G
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
    checks.push({ group, name, result: "finding", severity, observed, remediation, source: "dns" });
  };
  const pass = (name: string, observed: string, group = G) =>
    checks.push({ group, name, result: "pass", observed, source: "dns" });

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

  if (info.hasMx !== undefined) {
    if (!info.hasMx) {
      pass("MTA-STS", "no MX records (domain doesn't receive mail)");
    } else if (info.mtaSts === "missing" || info.mtaSts === "broken" || info.mtaSts === "none") {
      finding(
        "mta-sts-missing",
        "MTA-STS",
        info.mtaSts === "broken" ? "MTA-STS record without a policy file" : "No MTA-STS policy",
        info.mtaSts === "broken"
          ? `_mta-sts.${host} exists but https://mta-sts.${host}/.well-known/mta-sts.txt couldn't be read, so senders ignore it.`
          : "Mail servers sending to this domain will fall back to unencrypted delivery if an attacker strips STARTTLS. MTA-STS tells them to require TLS.",
        info.mtaSts === "broken" ? "TXT present, policy file unreadable" : info.mtaSts === "none" ? "mode: none" : "no _mta-sts record",
        "Publish an _mta-sts TXT record and a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt (start with mode: testing).",
        "low"
      );
    } else {
      pass("MTA-STS", `mode: ${info.mtaSts}`);
    }
  }

  if (info.caa !== undefined) {
    if (info.caa === null) {
      finding(
        "caa-missing",
        "CAA",
        "No CAA record",
        "Without a CAA record any certificate authority may issue certificates for this domain. CAA limits issuance to the CAs you actually use.",
        "none on the domain or its parents",
        'Add a CAA record such as: 0 issue "letsencrypt.org" (list each CA you use).',
        "low",
        "DNS"
      );
    } else {
      pass("CAA", `${info.caa.issuers.join(", ") || "issuance restricted"}${info.caa.name !== host ? ` (on ${info.caa.name})` : ""}`, "DNS");
    }
  }

  if (info.dnssec === false) {
    finding(
      "dnssec-disabled",
      "DNSSEC",
      "DNSSEC not enabled",
      "DNS answers for this domain aren't signed, so resolvers can't detect forged records (cache poisoning).",
      "answers not validated",
      "Enable DNSSEC at your DNS provider and add the DS record at your registrar.",
      "low",
      "DNS"
    );
  } else if (info.dnssec === true) {
    pass("DNSSEC", "signed and validated", "DNS");
  } else if (info.dnssec === null) {
    checks.push({ group: "DNS", name: "DNSSEC", result: "inconclusive", observed: "DNS-over-HTTPS resolver unreachable", source: "dns" });
  }

  return { findings, checks };
}

/** CAA applies from the closest name up: check the host, then each parent (not the TLD). */
async function findCaa(host: string): Promise<{ name: string; issuers: string[] } | null> {
  const labels = host.split(".");
  for (let i = 0; i <= labels.length - 2; i++) {
    const name = labels.slice(i).join(".");
    try {
      const records = await dns.resolveCaa(name);
      if (records.length) {
        const issuers = records.flatMap((r) => (r.issue ?? r.issuewild ? [String(r.issue ?? r.issuewild)] : []));
        return { name, issuers: [...new Set(issuers)] };
      }
    } catch {
      // no CAA here; keep climbing
    }
  }
  return null;
}

/** DNSSEC via a validating DoH resolver's AD (authenticated data) flag. */
async function dnssecValidated(host: string): Promise<boolean | null> {
  const resolvers = [
    `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A&do=1`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A&do=1`,
  ];
  for (const url of resolvers) {
    try {
      const res = await fetchWithTimeout(url, { timeoutMs: 5000, headers: { accept: "application/dns-json" } });
      if (!res.ok) continue;
      const body = (await res.json()) as { Status?: number; AD?: boolean };
      if (body.Status !== 0) continue;
      return body.AD === true;
    } catch {
      // try the next resolver
    }
  }
  return null;
}

async function mtaStsMode(host: string): Promise<DnsInfo["mtaSts"]> {
  const txt = await resolveTxt(`_mta-sts.${host}`);
  if (!txt.some((r) => /v=STSv1/i.test(r))) return "missing";
  try {
    const res = await fetchWithTimeout(`https://mta-sts.${host}/.well-known/mta-sts.txt`, { timeoutMs: 5000 });
    if (!res.ok) return "broken";
    const mode = /^mode:\s*(enforce|testing|none)\s*$/im.exec(await res.text());
    return mode ? (mode[1].toLowerCase() as "enforce" | "testing" | "none") : "broken";
  } catch {
    return "broken";
  }
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

  if (isLocalTarget(host)) return dnsAdapter(host, { hasSpf, spfRecord, hasDmarc, dmarcPolicy, hasDkim });
  const [mx, caa, dnssec] = await Promise.all([
    dns.resolveMx(host).catch(() => []),
    findCaa(host),
    dnssecValidated(host),
  ]);
  const hasMx = mx.length > 0;
  const mtaSts = hasMx ? await mtaStsMode(host) : undefined;
  return dnsAdapter(host, { hasSpf, spfRecord, hasDmarc, dmarcPolicy, hasDkim, hasMx, mtaSts, caa, dnssec });
}
