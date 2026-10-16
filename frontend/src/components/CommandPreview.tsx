import type { Check } from "../types";
import { CopyBlock } from "./CopyBlock";

interface CommandPreviewProps {
  mode: "repo" | "domain";
  target: string;
  attested: boolean;
  checks: Check[];
  selected: Set<string>;
  failOn: string;
  triage: boolean;
  fullHistory: boolean;
  baseRef: string;
  headRef: string;
  providerId: string | null;
}

/** Shell-quote a value only when it needs it. */
function q(v: string): string {
  return /^[\w@%+=:,./~-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`;
}

export const SKILL_INSTALL = "npx skills add adarshm07/scanner -g -a claude-code -a codex";

const CHECK_WORDS: Record<string, string> = {
  secrets: "secrets",
  sast: "code (SAST)",
  deps: "dependencies",
};

function joinWords(words: string[]): string {
  return words.length < 2 ? words.join("") : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/** A plain-English request for the Scanner-X agent skill matching the form. */
export function skillPrompt(p: Omit<CommandPreviewProps, "mode" | "attested" | "providerId" | "triage">): string {
  const chosen = p.checks.filter((c) => p.selected.has(c.id));
  const parts = [p.target.trim() ? `Scan ${p.target.trim()} with Scanner-X` : "Scan this repo with Scanner-X"];
  if (p.baseRef && p.headRef) parts.push(`, only the changes from ${p.baseRef} to ${p.headRef}`);
  else if (p.baseRef) parts.push(`, only the changes since ${p.baseRef}`);
  if (p.fullHistory) parts.push(", including the full git history for secrets");
  let text = parts.join("") + ".";
  if (chosen.length && chosen.length < p.checks.length) {
    text += ` Check ${joinWords(chosen.map((c) => CHECK_WORDS[c.id] ?? c.name.toLowerCase()))} only.`;
  }
  if (p.failOn !== "high") text += ` Fail on ${p.failOn} and above.`;
  return text;
}

/**
 * How to run the current scan yourself. Repo scans: the agent skill (it sets up the
 * scanners itself and does the triage, so no API key). Domain scans: the HTTP API (the
 * skill and CLI only scan repositories).
 */
export function CommandPreview(p: CommandPreviewProps) {
  const chosen = p.checks.filter((c) => p.selected.has(c.id)).map((c) => c.id);
  const target = p.target.trim();

  if (p.mode === "repo") {
    return (
      <div className="flex flex-col gap-2">
        <CopyBlock label="1 · Install the skill (once)" text={SKILL_INSTALL} wrap />
        <CopyBlock label="2 · Ask Claude Code or Codex" text={skillPrompt(p)} wrap />
      </div>
    );
  }

  const body = JSON.stringify({
    domain: target || "<host>",
    attested: p.attested,
    checks: chosen,
    failOn: p.failOn,
    triage: p.triage,
    ...(p.triage && p.providerId ? { provider: p.providerId } : {}),
  });
  const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost:5173";
  const text = [
    `curl -X POST ${origin}/api/scan/domain \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -d ${q(body)}`,
  ].join("\n");
  return <CopyBlock label="API" text={text} />;
}
