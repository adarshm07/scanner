import { CheckResult, Finding, makeFindingId, Severity } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout } from "./util";

interface CspSource {
  raw: string;
  source: "header" | "meta";
}

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function metaCsp(html: string): string | null {
  const tags = html.match(/<meta\b[^>]*>/gi) ?? [];
  for (const tag of tags) {
    const httpEquiv = tag.match(/http-equiv\s*=\s*["']?([^\s"'>]+)/i)?.[1];
    if (httpEquiv?.toLowerCase() !== "content-security-policy") continue;
    return tag.match(/content\s*=\s*["']([^"']*)["']/i)?.[1]?.trim() ?? null;
  }
  return null;
}

function directives(raw: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const directive of raw.split(";")) {
    const tokens = directive.trim().split(/\s+/).filter(Boolean);
    if (tokens.length > 0) result.set(tokens[0].toLowerCase(), tokens.slice(1).map((t) => t.toLowerCase()));
  }
  return result;
}

function cspIssues(raw: string): { id: string; severity: Severity; title: string }[] {
  const parsed = directives(raw);
  const script = parsed.get("script-src") ?? [];
  const defaultSrc = parsed.get("default-src") ?? [];
  const issues: { id: string; severity: Severity; title: string }[] = [];
  if (script.includes("'unsafe-inline'")) {
    issues.push({ id: "unsafe-inline", severity: "high", title: "CSP allows unsafe-inline scripts" });
  }
  if (script.includes("'unsafe-eval'")) {
    issues.push({ id: "unsafe-eval", severity: "high", title: "CSP allows unsafe-eval scripts" });
  }
  if (script.includes("*") || defaultSrc.includes("*")) {
    issues.push({ id: "wildcard-script-src", severity: "high", title: "CSP allows wildcard script sources" });
  }
  if (!(parsed.get("object-src") ?? []).includes("'none'")) {
    issues.push({ id: "object-src-not-none", severity: "medium", title: "CSP does not restrict object-src to 'none'" });
  }
  if (!parsed.has("base-uri")) {
    issues.push({ id: "missing-base-uri", severity: "low", title: "CSP is missing a base-uri directive" });
  }
  if (!parsed.has("default-src")) {
    issues.push({ id: "missing-default-src", severity: "medium", title: "CSP is missing a default-src directive" });
  }
  return issues;
}

export function cspAdapter(domain: string, source: CspSource | null): DomainResult {
  const url = `https://${domain}`;
  if (!source) {
    const finding: Finding = {
      skill: "csp-strength",
      category: "domain",
      finding_id: makeFindingId({ domain, check: "csp-missing", rule_id: "csp-strength" }),
      rule_id: "csp-strength",
      severity: "high",
      confidence: "high",
      title: "No Content-Security-Policy configured",
      location: { url },
      raw_snippet: null,
      tool_message: "No Content-Security-Policy header or meta policy was observed.",
      metadata: { all_issues: ["missing-csp"], csp_raw: "" },
    };
    return {
      findings: [finding],
      checks: [{
        group: "Content-Security-Policy",
        name: "CSP policy",
        result: "finding",
        severity: "high",
        observed: "absent",
        remediation: "Configure a restrictive Content-Security-Policy response header.",
        source: "csp-strength",
      }],
    };
  }

  const issues = cspIssues(source.raw);
  if (issues.length === 0) {
    return {
      findings: [],
      checks: [{
        group: "Content-Security-Policy",
        name: "CSP policy",
        result: "pass",
        observed: source.raw,
        source: "csp-strength",
      }],
    };
  }

  const worst = [...issues].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];
  const finding: Finding = {
    skill: "csp-strength",
    category: "domain",
    finding_id: makeFindingId({ domain, check: "csp-weakness", rule_id: "csp-strength" }),
    rule_id: "csp-strength",
    severity: worst.severity,
    confidence: "high",
    title: worst.title,
    location: { url },
    raw_snippet: null,
    tool_message: source.raw,
    metadata: { all_issues: issues.map((issue) => issue.id), csp_raw: source.raw, source: source.source },
  };
  return {
    findings: [finding],
    checks: [{
      group: "Content-Security-Policy",
      name: "CSP policy",
      result: "finding",
      severity: worst.severity,
      observed: source.raw,
      remediation: `Address: ${issues.map((issue) => issue.title).join("; ")}.`,
      source: "csp-strength",
    }],
  };
}

export async function runCspCheck(domain: string): Promise<DomainResult> {
  try {
    const response = await fetchWithTimeout(`https://${domain}`, { timeoutMs: 5000 });
    const header = response.headers.get("content-security-policy")?.trim();
    if (header) return cspAdapter(domain, { raw: header, source: "header" });
    const html = await response.text();
    const meta = metaCsp(html);
    return cspAdapter(domain, meta ? { raw: meta, source: "meta" } : null);
  } catch {
    return cspAdapter(domain, null);
  }
}
