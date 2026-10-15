import { useState } from "react";
import type { ReportFinding, Severity } from "../types";
import { SEVERITY_META, SeverityGlyph } from "./Severity";

const VERDICT: Record<string, { label: string; color: string }> = {
  true_positive: { label: "true positive", color: "#F28C38" },
  false_positive: { label: "false positive", color: "#56B982" },
  needs_review: { label: "needs review", color: "#8D979F" },
};

function scannerOf(finding: ReportFinding): string {
  return finding.skill.split("-")[0];
}

function locationOf(finding: ReportFinding): string {
  const { file, line_start, url } = finding.location;
  if (file) return line_start ? `${file}:${line_start}` : file;
  if (url) return url.replace(/^https?:\/\//, "");
  return "—";
}

export function FindingCard({ finding }: { finding: ReportFinding }) {
  const [open, setOpen] = useState(false);
  const severity: Severity = finding.triage?.adjusted_severity ?? finding.severity;
  const meta = SEVERITY_META[severity];
  const verdict = finding.triage ? VERDICT[finding.triage.verdict] : null;
  const cwe = typeof finding.metadata?.cwe === "string" ? finding.metadata.cwe : null;
  const owasp = typeof finding.metadata?.owasp === "string" ? finding.metadata.owasp : null;

  return (
    <div id={`f-${finding.finding_id}`} className="flex flex-col border-b border-line2">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="grid w-full grid-cols-[104px_minmax(0,1fr)_170px_84px_110px_16px] items-center gap-4 border-0 bg-transparent px-5 py-3 text-left hover:bg-hover"
      >
        <span className="flex items-center gap-2">
          <SeverityGlyph severity={severity} />
          <span className="font-mono text-[13px] font-medium" style={{ color: meta.color }}>
            {severity}
          </span>
        </span>
        <span className="truncate text-[14.5px] font-medium">{finding.title}</span>
        <span className="truncate font-mono text-[12.5px] text-text3">{locationOf(finding)}</span>
        <span className="truncate font-mono text-[12.5px] text-muted">{scannerOf(finding)}</span>
        <span className="truncate text-[13px]" style={{ color: verdict?.color ?? "#8D979F" }}>
          {verdict?.label ?? "—"}
        </span>
        <svg
          width={12}
          height={12}
          viewBox="0 0 12 12"
          aria-hidden="true"
          className={`transition-transform ${open ? "rotate-90" : ""}`}
        >
          <path d="M4 2 L8 6 L4 10" fill="none" stroke="#8D979F" strokeWidth={1.6} />
        </svg>
      </button>

      {open && (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-8 px-5 pb-7 pl-[42px] pt-1.5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="flex flex-col gap-[18px] text-[14px] leading-[1.6] text-text2">
            <div className="flex flex-col gap-1.5">
              <h4 className="m-0 text-[13px] font-semibold text-ink3">What the scanner found</h4>
              <p className="m-0">{finding.tool_message}</p>
            </div>
            {finding.triage?.suggested_fix && (
              <div className="flex flex-col gap-1.5">
                <h4 className="m-0 text-[13px] font-semibold text-ink3">Fix</h4>
                <p className="m-0 whitespace-pre-line">{finding.triage.suggested_fix}</p>
              </div>
            )}
            {finding.triage?.explanation && (
              <div className="flex flex-col gap-1.5">
                <h4 className="m-0 text-[13px] font-semibold text-ink3">Triage</h4>
                <p className="m-0">{finding.triage.explanation}</p>
              </div>
            )}
            <dl className="m-0 grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 gap-y-1.5 border-t border-line pt-3 text-[12.5px]">
              <dt className="text-muted">Rule</dt>
              <dd className="m-0 break-all font-mono">{finding.rule_id}</dd>
              {cwe && (
                <>
                  <dt className="text-muted">CWE</dt>
                  <dd className="m-0 font-mono">{cwe}</dd>
                </>
              )}
              {owasp && (
                <>
                  <dt className="text-muted">OWASP</dt>
                  <dd className="m-0">{owasp}</dd>
                </>
              )}
              <dt className="text-muted">ID</dt>
              <dd className="m-0 font-mono">{finding.finding_id}</dd>
            </dl>
          </div>

          {finding.raw_snippet && (
            <figure className="m-0 min-w-0 self-start overflow-hidden border border-line bg-ink2">
              <figcaption className="flex items-center gap-3 border-b border-line bg-panel px-3.5 py-2 text-[12.5px]">
                <span className="font-mono text-ink3">{locationOf(finding)}</span>
                <span className="text-muted">context</span>
              </figcaption>
              <div className="overflow-x-auto">
                {finding.raw_snippet.split("\n").map((line, i) => {
                  const m = /^(\d+): ?(.*)$/.exec(line);
                  const lineNo = m ? m[1] : "";
                  const code = m ? m[2] : line;
                  const isTarget =
                    finding.location.line_start != null &&
                    lineNo === String(finding.location.line_start);
                  return (
                    <div
                      key={i}
                      className={`grid grid-cols-[48px_minmax(0,1fr)] font-mono text-[12.5px] leading-[1.6] ${
                        isTarget ? "bg-sev-high/10" : ""
                      }`}
                    >
                      <span className="select-none border-r border-line px-2 text-right text-dim">
                        {lineNo}
                      </span>
                      <pre className="m-0 whitespace-pre px-3 text-text3">{code || " "}</pre>
                    </div>
                  );
                })}
              </div>
            </figure>
          )}
        </div>
      )}
    </div>
  );
}
