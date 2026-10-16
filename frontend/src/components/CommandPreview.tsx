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

const CLI = "node ~/.scanner-x/backend/dist/cli.js";

/** Shell-quote a value only when it needs it. */
function q(v: string): string {
  return /^[\w@%+=:,./~-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`;
}

function repoDir(url: string): string {
  const last = url.replace(/\/+$/, "").split("/").pop() ?? "";
  return last.replace(/\.git$/, "") || "repo";
}

/**
 * Runnable equivalent of the current form: the local CLI for repo scans (set up from the
 * "Terminal" tab below), the HTTP API for domain scans (the CLI only scans repositories).
 */
export function CommandPreview(p: CommandPreviewProps) {
  const chosen = p.checks.filter((c) => p.selected.has(c.id)).map((c) => c.id);
  const target = p.target.trim();

  if (p.mode === "repo") {
    const url = target || "<repo url>";
    const dir = target ? repoDir(target) : "<repo>";
    const flags = [
      "--path .",
      chosen.length && chosen.length < p.checks.length ? `--checks ${chosen.join(",")}` : null,
      p.baseRef ? `--base ${q(p.baseRef)}` : null,
      p.fullHistory ? "--full-history" : null,
      `--fail-on ${p.failOn}`,
      p.triage && p.providerId ? `--triage ${p.providerId}` : null,
    ].filter((f): f is string => !!f);
    const lines = [
      `git clone ${q(url)}`,
      `cd ${q(dir)}`,
      ...(p.baseRef && p.headRef ? [`git checkout ${q(p.headRef)}`] : []),
      `${CLI} \\\n  ${flags.join(" \\\n  ")}`,
    ];
    return <CopyBlock label="Terminal" text={lines.join("\n")} />;
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
