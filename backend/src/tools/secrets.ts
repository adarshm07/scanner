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

/** PEM header/footer lines ("-----BEGIN RSA PRIVATE KEY-----") carry no secret material. */
const PEM_ARMOR = /^-----(BEGIN|END) [A-Z0-9 ]+-----$/;

/**
 * Shortest run of a secret that is masked when it shows up on its own. Code often repeats
 * part of a secret (a test asserting `!out.includes("MIICXgIBAAKB…")`, a log prefix, a
 * truncated copy), and whole-value matching misses those. 10 random characters are long
 * enough not to collide with ordinary identifiers.
 */
const MIN_FRAGMENT_LENGTH = 10;
/** Runs of characters that secrets are made of (base64, base64url, hex, key prefixes). */
const TOKEN_RUN = /[A-Za-z0-9+/=_-]{10,}/g;

export function maskText(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (out.includes(s)) out = out.split(s).join(maskValue(s));
    // A multi-line secret (e.g. a private key) never matches a snippet whole, because
    // snippets carry "N: " line-number prefixes. Mask each of its lines on its own.
    if (s.includes("\n")) {
      for (const line of s.split(/\r?\n/).map((l) => l.trim())) {
        if (line.length < MIN_SECRET_LENGTH || PEM_ARMOR.test(line)) continue;
        if (out.includes(line)) out = out.split(line).join(maskValue(line));
      }
    }
  }
  return maskFragments(out, secrets);
}

/** Mask any run of text that is a piece (>= MIN_FRAGMENT_LENGTH chars) of a known secret. */
function maskFragments(text: string, secrets: string[]): string {
  const bodies = secrets
    .map((s) => s.split(/\r?\n/).filter((l) => !PEM_ARMOR.test(l.trim())).join("").replace(/\s+/g, ""))
    .filter((b) => b.length >= MIN_FRAGMENT_LENGTH);
  if (bodies.length === 0) return text;
  return text.replace(TOKEN_RUN, (run) => {
    // Already-masked values ("MIIC****") contain no secret material beyond 4 chars.
    if (run.endsWith("****")) return run;
    return bodies.some((b) => b.includes(run) || containsFragment(run, b)) ? maskValue(run) : run;
  });
}

/** True when `run` contains a MIN_FRAGMENT_LENGTH-long piece of `body`. */
function containsFragment(run: string, body: string): boolean {
  for (let i = 0; i + MIN_FRAGMENT_LENGTH <= run.length; i++) {
    if (body.includes(run.slice(i, i + MIN_FRAGMENT_LENGTH))) return true;
  }
  return false;
}

/** Private-key material that no detector reported (PEM blocks, DER/base64 key bodies). */
const PEM_ARMOR_ANY = /-----(BEGIN|END) [A-Z0-9 ]*PRIVATE KEY-----/g;
const KEY_BODY = /\bMII[A-Za-z0-9+/]{17,}={0,2}/g;

/**
 * Last line of defense before text leaves for the LLM gateway: redact anything that looks
 * like private-key material, whether or not a scanner reported it. Line structure is kept
 * so line-numbered snippets still line up. PEM armor is replaced too, since gateway secret
 * detectors match on the header alone.
 */
export function scrubKeyMaterial(text: string): string {
  return text
    .replace(PEM_ARMOR_ANY, (_m, edge: string) => `[private key ${edge === "BEGIN" ? "start" : "end"}]`)
    .replace(KEY_BODY, "MII****");
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
