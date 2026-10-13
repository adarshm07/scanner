import type { Check } from "../types";

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
}

/**
 * Live CLI equivalent of the current form selections (design "command" panel).
 */
export function CommandPreview({
  mode,
  target,
  attested,
  checks,
  selected,
  failOn,
  triage,
  fullHistory,
  baseRef,
  headRef,
}: CommandPreviewProps) {
  const chosen = checks.filter((c) => selected.has(c.id)).map((c) => c.id);
  const t = target.trim() || (mode === "repo" ? "<owner/repo>" : "<host>");

  const lines: string[] = [
    `$ scanner-x scan ${mode} ${t} \\`,
    ...(mode === "domain"
      ? [`    --attest ${attested ? "authorized" : "<required>"} \\`]
      : []),
    `    --checks ${chosen.join(",") || "<none>"} \\`,
    ...(mode === "repo" && fullHistory ? ["    --full-history \\"] : []),
    ...(mode === "repo" && baseRef ? [`    --base ${baseRef} \\`] : []),
    ...(mode === "repo" && baseRef && headRef ? [`    --head ${headRef} \\`] : []),
    `    --fail-on ${failOn}${triage ? " \\" : ""}`,
    ...(triage ? ["    --triage"] : []),
  ];

  return (
    <figure className="m-0 border border-line bg-ink2">
      <figcaption className="border-b border-line bg-panel px-3 py-1.5 text-[11.5px] text-muted">
        Command
      </figcaption>
      <pre className="m-0 overflow-x-auto p-3 font-mono text-[12px] leading-[1.7] text-text3">
        {lines.join("\n")}
      </pre>
    </figure>
  );
}
