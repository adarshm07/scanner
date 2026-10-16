import { Finding } from "../schema/finding";

/**
 * Secret masking.
 *
 * gitleaks reports the secret value it found. Scanner-X needs that value only long enough
 * to mask it everywhere else: code snippets (read from disk after detection), messages and
 * metadata, for every finding, since another tool's snippet can include the same line.
 * Masking runs before triage, so the value never reaches an LLM, its gateway logs, the
 * saved report, JSON or SARIF output.
 *
 * The raw value is attached to the finding as a NON-enumerable property: JSON
 * serialization and object spreads drop it, so it can't leak by being copied along.
 */

const SECRET_KEY = "__scannerXSecret";
/** Shorter values are too likely to match unrelated text, and too short to be useful keys. */
const MIN_SECRET_LENGTH = 6;

export function attachSecret(finding: Finding, value: string | undefined): void {
  const v = value?.trim();
  if (!v || v.length < MIN_SECRET_LENGTH) return;
  Object.defineProperty(finding, SECRET_KEY, { value: v, enumerable: false, configurable: true });
}

/** All distinct secret values attached to these findings, longest first. */
export function secretsOf(findings: Finding[]): string[] {
  const set = new Set<string>();
  for (const f of findings) {
    const v = (f as unknown as Record<string, unknown>)[SECRET_KEY];
    if (typeof v === "string") set.add(v);
  }
  // Longest first, so a secret containing another is replaced as a whole.
  return [...set].sort((a, b) => b.length - a.length);
}

/** "sk_live_51Hx…" -> "sk_l****"; short values are fully hidden. */
export function maskValue(value: string): string {
  return value.length >= 12 ? `${value.slice(0, 4)}****` : "****";
}

export function maskText(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (out.includes(s)) out = out.split(s).join(maskValue(s));
  }
  return out;
}

function maskDeep(value: unknown, secrets: string[]): unknown {
  if (typeof value === "string") return maskText(value, secrets);
  if (Array.isArray(value)) return value.map((v) => maskDeep(v, secrets));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskDeep(v, secrets)]));
  }
  return value;
}

/** Mask every text field of a finding in place. */
export function maskFinding(finding: Finding, secrets: string[]): void {
  if (secrets.length === 0) return;
  finding.title = maskText(finding.title, secrets);
  finding.tool_message = maskText(finding.tool_message, secrets);
  if (finding.raw_snippet) finding.raw_snippet = maskText(finding.raw_snippet, secrets);
  finding.metadata = maskDeep(finding.metadata, secrets) as Finding["metadata"];
}
