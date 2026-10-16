import {
  Category,
  Finding,
  Severity,
  TriageResult,
  Verdict,
} from "../schema/finding";
import { callLlmJson, LlmProvider } from "../llm";
import { triageStore } from "../store/reportStore";

/**
 * Step 4 of the pipeline (Spec Section 5.4): batched LLM triage.
 *
 * For each category group, make ONE batched LLM call covering all findings in
 * that group (batches of <=20). Cache results by finding_id so re-running on an
 * unchanged file/domain skips the LLM call entirely. When no provider is
 * available, fall back to a deterministic pass-through verdict.
 */

const BATCH_SIZE = 20;

const SYSTEM_PROMPT = `You are a security triage assistant reviewing findings produced by deterministic scanning tools (secret detection, static analysis, dependency/CVE lookup, and configuration checks). Your job is judgment, not detection — the tools already found these; you decide how much each one actually matters in context, and explain why in plain language a developer can act on.

For EACH finding provided, return:
- adjusted_severity: one of "critical", "high", "medium", "low"
- verdict: one of "true_positive" (real, confirmed), "false_positive" (likely a false positive), "needs_review" (needs manual review)
- explanation: 2-4 sentences, plain language. Cover, in order: what is actually wrong, the realistic impact if an attacker exploits it (or the realistic benign cause if it is likely a scan artifact), and how likely/urgent it is for THIS target. Name the specific host, file, header, or package involved.
- suggested_fix: a short numbered list of concrete steps (separated by "\n"), most likely cause first. Include exact commands, config snippets, header values, or version bumps where applicable (e.g. an openssl command, an nginx/Apache directive, a DNS record). End with one step explaining how to verify the fix. Never answer with only "verify" or "investigate" — give the developer something to run or change.

General principles for every finding:
- Do not simply restate the tool's severity as your adjusted_severity — that defeats the purpose of this step. Only match it when your own reasoning independently arrives at the same conclusion.
- Do not copy the scanner's tool_message verbatim into your explanation; add analyst context (impact, exploitability, or a confidence caveat).
- Consider whether the flagged input is actually attacker-controlled, reachable from an untrusted boundary, and not already mitigated elsewhere in the same file or a wrapping function.
- If two or more findings in this batch clearly relate to the same underlying issue (e.g. a CSP weakness and an XSS-pattern match on the same file, or a missing-auth finding and an exposed-endpoint finding on the same route), say so explicitly in both explanations rather than triaging them as unrelated. Do not merge them into one finding — keep them separate, just note the relationship.

Apply the guidance block matching each finding's "skill" field (matched by prefix):

gitleaks-* (secret detection): Treat the verdict as "true_positive" unless the secret is clearly a placeholder, example, or test fixture value (e.g. matches a widely-published example key like AWS's AKIAIOSFODNN7EXAMPLE, or sits in a file path containing "test", "fixture", "example", or "mock"). Real secrets in real code paths are almost never false positives — do not downgrade severity just because a key looks old or might be rotated already; you cannot verify that.

semgrep-* (SAST patterns): Check whether the flagged input is genuinely attacker-controlled at this call site — a string built from a hardcoded enum or a value that never leaves server-side config is not the same risk as one built from req.query/req.body/req.params. Set verdict "false_positive" only when you can point to the specific line that makes the input non-attacker-controlled; do not downgrade on a guess.

npm-audit-* and osv-* (dependency and CVE findings; osv-* covers Python, Java, Rust, Go and other ecosystems): These carry a CVE ID and upstream description — use it. If the CVE description specifies the vulnerability requires a particular feature to be in use (e.g. requires Next.js Middleware or the Image Optimization API), check whether this repo's code actually uses that feature before treating it as immediately exploitable. If the feature is not used: keep verdict "true_positive" (the vulnerable dependency is still real) but lower adjusted_severity by one level and say explicitly in the explanation that the vulnerable feature does not appear to be in use here. Never dismiss a CVE finding entirely just because a feature looks unused — say it is lower priority, do not erase it.

csp-strength: Look at how much of the policy is actually weakened, not just whether a weakness pattern is present. 'unsafe-inline' applied narrowly (e.g. only in script-src, with a scoped nonce/hash also present, or clearly limited to a single known third-party tag) is a smaller real risk than 'unsafe-inline' with no other mitigation and a permissive default-src. Read the full CSP string provided in metadata before deciding severity — do not judge from the issue label alone.

cookie-security-* (cookie security flags): Missing SameSite alone is low severity — browser defaults vary and this is rarely the sole enabler of an attack. Missing HttpOnly is only high severity if the cookie name or context suggests it holds a session/auth token; a clearly non-sensitive cookie (theme, locale, consent-banner state) missing HttpOnly is low, regardless of what the deterministic check assigned. Use the surrounding cookies set in the same response and the app's apparent purpose to judge sensitivity.

cors-* (CORS misconfiguration): A wildcard or reflected Access-Control-Allow-Origin WITHOUT Access-Control-Allow-Credentials is often an intentional public API design choice — do not default to high severity for this combination alone. Reserve high/critical for the specific combination of a reflected or wildcarded origin together with credentials allowed, which lets arbitrary sites make authenticated requests and read the responses.

tls-* (certificate/TLS checks): The scanner has already diagnosed the cause and collected the evidence: metadata.cause (self-signed | missing-intermediate | private-ca | expired-chain | unknown), metadata.chain (leaf first, root last), metadata.authorizationError, metadata.sslLabsGrade (a public-internet vantage point, or null when no cached result), and metadata.altNames for hostname mismatches. Base your verdict on that evidence and name the specific certificates involved. Findings caused by an HTTPS-inspecting proxy on the scanner's side are already filtered out, so do not suggest that as the default explanation, and never tell the reader to \"verify from another network\": the scanner already cross-checked with SSL Labs where possible. For private-ca, say it is expected for internal-only hosts and only a problem if the site is public. Explanation: the impact on real visitors (browser warnings, failing API clients and webhooks, interception risk). suggested_fix: the remedy for the diagnosed cause with the exact command or server directive (e.g. nginx ssl_certificate fullchain.pem, certbot), then end with the command in metadata.verifyCommand as the verification step.

header-* (HTTP security headers): State what attack the missing/weak header enables and give the exact header line to add plus where to set it (nginx add_header, Express helmet, CDN rule). Do not rate a missing informational header above low.

dns-* (SPF/DMARC/DNSSEC etc.): Explain the concrete abuse (e.g. spoofed email from the domain) and give the exact TXT record to publish, starting from a safe value and noting any staged rollout (e.g. DMARC p=none then quarantine).

subdomain-ct-enumeration: This is informational attack-surface data. Point out which subdomains look sensitive (staging, admin, internal, dev, vpn) and recommend reviewing or decommissioning them; keep severity low unless a clearly sensitive name is exposed.

exposed-sensitive-file: The detection logic already validates the response body shape (e.g. requires recognizable git config syntax or env-variable syntax) before emitting a finding, so false positives here are very unlikely. Keep the tool's assigned severity unless you have a specific, stated reason to change it — do not downgrade this one on general "might be a false positive" reasoning.

Respond ONLY with valid JSON matching the schema described in the user message. Do not invent new findings.`;

interface TriageLlmResponse {
  results: {
    finding_id: string;
    verdict: Verdict;
    adjusted_severity: Severity;
    explanation: string;
    suggested_fix: string;
  }[];
}

export interface TriageCategoryOutput {
  results: Map<string, TriageResult>;
  llmFallbackUsed: boolean;
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}

/** Only send the fields the model needs; keeps the payload (and cost) small. */
function forLlm(f: Finding) {
  return {
    finding_id: f.finding_id,
    rule_id: f.rule_id,
    severity: f.severity,
    confidence: f.confidence,
    title: f.title,
    location: f.location,
    tool_message: f.tool_message,
    raw_snippet: f.raw_snippet,
    metadata: f.metadata,
  };
}

function passthrough(f: Finding): TriageResult {
  return {
    finding_id: f.finding_id,
    verdict: "needs_review",
    adjusted_severity: f.severity,
    explanation: f.tool_message,
    // Use the check's own remedy when it has one (e.g. TLS findings), not a generic line.
    suggested_fix:
      typeof f.metadata?.remediation === "string" && f.metadata.remediation
        ? f.metadata.remediation
        : "Review the flagged code/configuration and remediate per the tool guidance.",
  };
}

function normalizeText(s: string): string {
  return s.toLowerCase().replace(/\s+/g, " ").trim();
}

function nearDuplicate(a: string, b: string): boolean {
  if (!a || !b) return false;
  const na = normalizeText(a);
  const nb = normalizeText(b);
  if (na === nb || na.includes(nb) || nb.includes(na)) return true;
  // Prefix similarity catches tiny punctuation/Unicode variations.
  const min = Math.min(na.length, nb.length);
  if (min < 24) return false;
  return na.slice(0, Math.floor(min * 0.7)) === nb.slice(0, Math.floor(min * 0.7));
}

function locationLabel(f: Finding): string {
  if (f.location.file) {
    return f.location.line_start
      ? `${f.location.file}:${f.location.line_start}`
      : f.location.file;
  }
  return f.location.url ?? "the affected target";
}

function fallbackFix(f: Finding): string {
  return `Investigate ${locationLabel(
    f
  )} for rule ${f.rule_id}, apply the scanner's remediation guidance, and add a regression check to prevent recurrence.`;
}

function isGenericFix(s: string): boolean {
  const n = normalizeText(s);
  return (
    n.includes("remediate per the tool guidance") ||
    n.includes("review the flagged code/configuration")
  );
}

async function triageBatch(
  provider: LlmProvider,
  category: Category,
  repoName: string,
  batch: Finding[]
): Promise<TriageResult[]> {
  const user = `Here are ${batch.length} findings from category "${category}" in repo "${repoName}":\n${JSON.stringify(
    batch.map(forLlm),
    null,
    2
  )}\n\nReturn JSON: { "results": [ { "finding_id", "verdict": "true_positive"|"false_positive"|"needs_review", "adjusted_severity", "explanation", "suggested_fix" } ] }`;

  const response = await callLlmJson<TriageLlmResponse>(provider, {
    system: SYSTEM_PROMPT,
    user,
    maxTokens: 6000,
  });

  const byId = new Map(response.results.map((r) => [r.finding_id, r]));
  return batch.map((f) => {
    const r = byId.get(f.finding_id);
    if (!r) return passthrough(f);
    const rawExplanation = (r.explanation ?? "").trim();
    const rawFix = (r.suggested_fix ?? "").trim();
    const explanation =
      rawExplanation && !nearDuplicate(rawExplanation, f.tool_message)
        ? rawExplanation
        : `Scanner indicates: ${f.tool_message} Validate exploitability and business impact in your environment.`;
    const suggestedFix =
      rawFix && !nearDuplicate(rawFix, passthrough(f).suggested_fix) && !isGenericFix(rawFix)
        ? rawFix
        : fallbackFix(f);
    return {
      finding_id: f.finding_id,
      verdict: r.verdict,
      adjusted_severity: r.adjusted_severity ?? f.severity,
      explanation,
      suggested_fix: suggestedFix,
    };
  });
}

/**
 * Triage every finding in a category group. Returns a map keyed by finding_id.
 */
export async function triageCategory(
  provider: LlmProvider | null,
  category: Category,
  repoName: string,
  findings: Finding[]
): Promise<TriageCategoryOutput> {
  const out = new Map<string, TriageResult>();
  let llmFallbackUsed = false;

  // Serve cached verdicts only in deterministic mode. If a provider is active,
  // re-triage to avoid reusing stale pass-through results from earlier runs.
  const uncached: Finding[] = [];
  for (const f of findings) {
    if (provider) {
      uncached.push(f);
      continue;
    }
    const cached = triageStore.get(f.finding_id);
    if (cached) {
      out.set(f.finding_id, cached);
    } else {
      uncached.push(f);
    }
  }

  if (uncached.length === 0) return { results: out, llmFallbackUsed };

  if (!provider) {
    for (const f of uncached) {
      const result = passthrough(f);
      triageStore.set(result);
      out.set(f.finding_id, result);
    }
    return { results: out, llmFallbackUsed };
  }

  for (const batch of chunk(uncached, BATCH_SIZE)) {
    let results: TriageResult[];
    try {
      results = await triageBatch(provider, category, repoName, batch);
    } catch (err) {
      // On LLM failure, degrade gracefully to pass-through rather than fail scan.
      llmFallbackUsed = true;
      console.warn(
        `[triage] LLM fallback for ${category} (${batch.length} findings): ${(err as Error).message}`
      );
      results = batch.map(passthrough);
    }
    for (const r of results) {
      triageStore.set(r);
      out.set(r.finding_id, r);
    }
  }

  return { results: out, llmFallbackUsed };
}
