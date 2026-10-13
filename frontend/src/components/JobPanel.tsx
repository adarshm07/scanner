import type { Check } from "../types";
import { CommandPreview } from "./CommandPreview";

interface JobPanelProps {
  mode: "repo" | "domain";
  target: string;
  attested: boolean;
  checks: Check[];
  selected: Set<string>;
  failOn: string;
  triage: boolean;
  providerId: string | null;
  estimate: string;
  canSubmit: boolean;
  loading: boolean;
  onRun: () => void;
  error: string | null;
}

function touches(p: JobPanelProps): { k: string; v: string }[] {
  const t = p.target.trim() || (p.mode === "repo" ? "the repository" : "the host");
  const modelOn = p.triage && !!p.providerId;
  if (p.mode === "repo") {
    return [
      { k: "Reads", v: `A shallow clone of ${t}, deleted when the scan ends.` },
      { k: "Network", v: "Dependency and secret checks may query public advisory sources." },
      { k: "Model", v: modelOn ? "Finding metadata and up to 20 lines of context per finding." : "Nothing. Triage is off." },
    ];
  }
  return [
    { k: "Sends", v: `TLS handshakes and a few HTTP/DNS requests to ${t}.` },
    { k: "Does not", v: "Crawl, submit forms, send payloads or try credentials." },
    { k: "Model", v: modelOn ? "Check results and response headers. No page bodies." : "Nothing. Triage is off." },
  ];
}

export function JobPanel(props: JobPanelProps) {
  return (
    <div className="flex flex-col gap-6 lg:sticky lg:top-8">
      <h2 className="m-0 text-[15px] font-semibold">Job</h2>

      <div className="flex flex-col gap-2">
        <p className="text-[12.5px] text-muted">Equivalent CLI</p>
        <CommandPreview
          mode={props.mode}
          target={props.target}
          attested={props.attested}
          checks={props.checks}
          selected={props.selected}
          failOn={props.failOn}
          triage={props.triage}
        />
      </div>

      <div className="flex flex-col gap-2">
        <p className="text-[12.5px] text-muted">What this scan touches</p>
        <dl className="m-0 flex flex-col">
          {touches(props).map((row) => (
            <div
              key={row.k}
              className="grid grid-cols-[80px_minmax(0,1fr)] gap-4 border-t border-line py-3 text-[13px]"
            >
              <dt className="text-muted">{row.k}</dt>
              <dd className="m-0 text-text3">{row.v}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="flex flex-col gap-2 border-t border-line pt-5">
        {props.estimate && <p className="m-0 text-[12.5px] text-muted">{props.estimate}</p>}
        <button
          onClick={props.onRun}
          disabled={!props.canSubmit}
          className="h-11 w-full rounded bg-ink3 text-[14px] font-semibold text-ink transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-30"
        >
          {props.loading ? "Scanning…" : "Run scan"}
        </button>
        {props.mode === "domain" && !props.attested && (
          <p className="m-0 text-center text-[12px] text-muted">
            Confirm you are authorized to test this host.
          </p>
        )}
        {props.error && (
          <p className="m-0 rounded border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-[13px] text-sev-critical">
            {props.error}
          </p>
        )}
      </div>
    </div>
  );
}
