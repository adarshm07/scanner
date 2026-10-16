import { promises as dns } from "dns";
import { CheckResult, Finding, makeFindingId, Severity } from "../schema/finding";
import { readCapped } from "./exposedFiles";
import { fetchWithTimeout } from "./util";

/**
 * Subdomain takeover: a subdomain whose CNAME still points at a hosting service after the
 * resource there was deleted. Anyone can re-create that resource (a bucket, a Pages site,
 * an app) and serve content on the victim's subdomain — phishing, cookie theft, bypassing
 * CSP/CORS allowlists. Fingerprints follow the community list "can-i-take-over-xyz".
 */

interface Service {
  name: string;
  cname: RegExp;
  /** Body text the service shows when nothing is claimed at that name. */
  fingerprint?: RegExp;
  /** The service frees the name entirely: a CNAME to a non-existent name is claimable. */
  nxdomain?: boolean;
}

export const SERVICES: Service[] = [
  { name: "AWS S3", cname: /\.s3[.-][a-z0-9.-]*amazonaws\.com$|\.s3\.amazonaws\.com$/, fingerprint: /NoSuchBucket|The specified bucket does not exist/ },
  { name: "GitHub Pages", cname: /\.github\.io$/, fingerprint: /There isn't a GitHub Pages site here/ },
  { name: "Heroku", cname: /\.(herokuapp|herokudns|herokussl)\.com$/, fingerprint: /no-such-app|No such app/ },
  { name: "Bitbucket", cname: /\.bitbucket\.io$/, fingerprint: /Repository not found/ },
  { name: "Surge.sh", cname: /\.surge\.sh$/, fingerprint: /project not found/ },
  { name: "Pantheon", cname: /\.pantheonsite\.io$/, fingerprint: /The gods are wise, but do not know of the site which you seek/ },
  { name: "Ghost", cname: /\.ghost\.io$/, fingerprint: /Failed to resolve DNS path for this host/ },
  {
    name: "Microsoft Azure",
    cname: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azure-api\.net|azurefd\.net|azurecontainer\.io|azurestaticapps\.net)$/,
    nxdomain: true,
  },
];

export interface TakeoverDeps {
  /** CNAME targets of a name ([] when it has none). */
  cname(name: string): Promise<string[]>;
  /** Whether a name exists in DNS at all ("nx" when it does not). */
  exists(name: string): Promise<boolean | "nx">;
  /** Up to 64 KB of the page at the URL, or null if unreachable. */
  page(url: string): Promise<string | null>;
}

export interface Takeover {
  subdomain: string;
  cnameChain: string[];
  service: string | null;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  evidence: string;
}

/** Follow the CNAME chain (bounded) and decide whether this subdomain can be taken over. */
export async function assessSubdomain(sub: string, deps: TakeoverDeps): Promise<Takeover | null> {
  const chain: string[] = [];
  let current = sub;
  for (let i = 0; i < 5; i++) {
    const next = (await deps.cname(current))[0];
    if (!next) break;
    const target = next.toLowerCase().replace(/\.$/, "");
    if (chain.includes(target)) break;
    chain.push(target);
    current = target;
  }
  if (chain.length === 0) return null;

  const last = chain[chain.length - 1];
  const service = SERVICES.find((s) => chain.some((t) => s.cname.test(t))) ?? null;
  const exists = await deps.exists(last);

  if (service?.nxdomain && exists === "nx") {
    return {
      subdomain: sub, cnameChain: chain, service: service.name, severity: "high", confidence: "medium",
      evidence: `CNAME points to ${last}, which no longer exists. ${service.name} lets anyone create a resource with that name.`,
    };
  }
  if (service?.fingerprint) {
    for (const url of [`https://${sub}/`, `http://${sub}/`]) {
      const body = await deps.page(url);
      if (body && service.fingerprint.test(body)) {
        return {
          subdomain: sub, cnameChain: chain, service: service.name, severity: "high", confidence: "high",
          evidence: `CNAME points to ${last} and ${url} shows ${service.name}'s "nothing here" page, so the resource can be claimed.`,
        };
      }
    }
  }
  if (exists === "nx") {
    return {
      subdomain: sub, cnameChain: chain, service: service?.name ?? null, severity: "medium", confidence: "low",
      evidence: `Dangling CNAME: points to ${last}, which does not exist. If that domain or name can be registered, the subdomain can be taken over.`,
    };
  }
  return null;
}

const liveDeps: TakeoverDeps = {
  async cname(name) {
    try {
      return await dns.resolveCname(name);
    } catch {
      return [];
    }
  },
  async exists(name) {
    try {
      await dns.lookup(name);
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      return code === "ENOTFOUND" || code === "ENODATA" ? "nx" : false;
    }
  },
  async page(url) {
    try {
      const res = await fetchWithTimeout(url, { timeoutMs: 5000 });
      return (await readCapped(res)).toString("utf8");
    } catch {
      return null;
    }
  },
};

const MAX_SUBDOMAINS = 150;
const CONCURRENCY = 10;

export async function findTakeovers(subdomains: string[], deps: TakeoverDeps = liveDeps): Promise<{ results: Takeover[]; checked: number }> {
  const list = subdomains.slice(0, MAX_SUBDOMAINS);
  const results: Takeover[] = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, list.length) }, async () => {
      while (next < list.length) {
        const r = await assessSubdomain(list[next++], deps).catch(() => null);
        if (r) results.push(r);
      }
    })
  );
  results.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
  return { results, checked: list.length };
}

export function takeoverAdapter(host: string, found: Takeover[], checked: number, total: number): { findings: Finding[]; checks: CheckResult[] } {
  const G = "Subdomains";
  const findings: Finding[] = found.map((t) => ({
    skill: "subdomain-takeover",
    category: "domain",
    finding_id: makeFindingId({ domain: host, check: `takeover-${t.subdomain}`, rule_id: "subdomain-takeover" }),
    rule_id: "subdomain-takeover",
    severity: t.severity,
    confidence: t.confidence,
    title: t.confidence === "low" ? `Dangling CNAME on ${t.subdomain}` : `Subdomain takeover possible: ${t.subdomain}${t.service ? ` (${t.service})` : ""}`,
    location: { url: `https://${t.subdomain}` },
    raw_snippet: null,
    tool_message: t.evidence,
    metadata: {
      owasp: "A05:2021-Security Misconfiguration",
      cwe: "CWE-350",
      subdomain: t.subdomain,
      cnameChain: t.cnameChain,
      service: t.service,
      evidence: [`${t.subdomain} → ${t.cnameChain.join(" → ")}`],
    },
  }));
  const limited = checked < total ? ` (first ${checked} of ${total})` : "";
  const checks: CheckResult[] = found.length
    ? found.map((t) => ({
        group: G,
        name: `Takeover: ${t.subdomain}`,
        result: "finding",
        severity: t.severity,
        observed: `→ ${t.cnameChain[t.cnameChain.length - 1]}${t.service ? ` (${t.service})` : ""}`,
        remediation: "Delete the DNS record, or re-create the resource it points to in your own account.",
        source: "subdomains",
      }))
    : [{
        group: G,
        name: "Takeover",
        result: "pass",
        observed: `${checked} subdomains checked${limited}; none point at unclaimed services`,
        source: "subdomains",
      }];
  return { findings, checks };
}
