import type { Report, Severity } from "../types";
import { FindingCard } from "./FindingCard";
import { ChecksTable } from "./ChecksTable";
import { SEVERITY_META, SEVERITY_ORDER, SeverityGlyph } from "./Severity";

function severityOf(f: { severity: Severity; triage: { adjusted_severity: Severity } | null }): Severity {
  return f.triage?.adjusted_severity ?? f.severity;
}

/** Diff scans store `<base>...<head>`; show both sides so it's clear the head was scanned. */
function formatRef(ref: string): string {
  const [base, head] = ref.split("...");
  return head ? `${base.slice(0, 7)}…${head.slice(0, 7)}` : ref.slice(0, 12);
}

function failReason(policy: Report["policy"]): string {
  const parts: string[] = [];
  if (policy.reason) parts.push(policy.reason);
  if (policy.countAtOrAbove > 0) parts.push(`${policy.countAtOrAbove} at or above ${policy.failOn}`);
  return parts.join(" · ");
}

export function ReportView({
  report,
  onNewScan,
}: {
  report: Report;
  onNewScan?: () => void;
}) {
  const allFindings = report.categories.flatMap((c) => c.findings);
  const counts = report.stats.bySeverity;
  const total = report.stats.totalAfterFilter;

  // One cell per finding, most severe first — the severity "strip".
  const strip = [...allFindings].sort(
    (a, b) => SEVERITY_META[severityOf(a)].rank - SEVERITY_META[severityOf(b)].rank
  );

  return (
    <div className="border border-line bg-ink">
      {/* header */}
      <header className="flex h-[52px] shrink-0 items-center gap-7 border-b border-line px-6">
        <div className="text-[15px] font-semibold tracking-[-0.01em]">Scanner-X</div>
        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-[13px] text-muted">
          <span className="capitalize">{report.mode}</span>
          <span aria-hidden>/</span>
          <span className="max-w-[280px] truncate text-ink3">{report.target}</span>
        </nav>
        <div className="grow" />
        <span className="font-mono text-[12.5px] text-muted" title={report.ref}>{formatRef(report.ref)}</span>
        {report.ai.llmFallbackUsed && (
          <span className="rounded border border-sev-medium/50 bg-sev-medium/10 px-2 py-0.5 text-[11px] font-mono text-sev-medium">
            llm fallback used
          </span>
        )}
        {onNewScan && (
          <button
            onClick={onNewScan}
            className="h-8 rounded bg-ink3 px-3 text-[13px] font-medium text-ink transition-opacity hover:opacity-90"
          >
            New scan
          </button>
        )}
      </header>

      {report.warning && (
        <div role="alert" className="border-b border-sev-medium/40 bg-sev-medium/10 px-6 py-3 text-[13px] text-sev-medium">
          {report.warning}
        </div>
      )}

      {report.notes?.map((note) => (
        <div key={note} role="note" className="border-b border-line bg-panel/60 px-6 py-3 text-[13px] text-text3">
          {note}
        </div>
      ))}

      {/* title + meta */}
      <section className="flex flex-col gap-5 px-6 pt-7">
        <div className="flex items-baseline gap-4">
          <h1 className="m-0 text-[26px] font-semibold tracking-[-0.02em]">{report.target}</h1>
          <span className="font-mono text-[13px] text-muted capitalize">{report.mode} scan</span>
        </div>
        <dl className={`m-0 grid grid-cols-2 gap-4 text-[13px] ${report.diff ? "sm:grid-cols-5" : "sm:grid-cols-4"}`}>
          {[
            ["Ref", formatRef(report.ref)],
            ...(report.diff
              ? [["Diff", `${report.diff.changedFiles} ${report.diff.changedFiles === 1 ? "file" : "files"} changed vs ${report.diff.baseRef}`]]
              : []),
            ["Findings", `${total} of ${report.stats.totalRaw} raw`],
            ["Policy", `--fail-on ${report.policy.failOn}`],
            ["Finished", new Date(report.createdAt).toLocaleString()],
          ].map(([k, v]) => (
            <div key={k} className="flex flex-col gap-1">
              <dt className="text-muted">{k}</dt>
              <dd className="m-0 font-mono text-text3">{v}</dd>
            </div>
          ))}
        </dl>
        <div className="flex items-center gap-2 text-[13px]">
          {report.policy.passed ? (
            <>
              <svg width={12} height={12} viewBox="0 0 12 12" aria-hidden="true">
                <path d="M2.5 6.5 L5 9 L9.5 3.5" fill="none" stroke="#56B982" strokeWidth={2} />
              </svg>
              <span className="font-mono text-[#56B982]">
                policy passed — nothing at or above {report.policy.failOn}
              </span>
            </>
          ) : (
            <>
              <svg width={12} height={12} viewBox="0 0 12 12" aria-hidden="true">
                <path d="M2 2 L10 10 M10 2 L2 10" stroke="#F0506E" strokeWidth={2} />
              </svg>
              <span className="font-mono text-sev-critical">
                check failed — {failReason(report.policy)}
              </span>
            </>
          )}
        </div>
      </section>

      {/* severity overview */}
      <section aria-label="Severity overview" className="flex flex-col gap-3.5 px-6 pt-8">
        <div className="flex flex-wrap items-end gap-x-12 gap-y-4">
          {SEVERITY_ORDER.map((s) => {
            const meta = SEVERITY_META[s];
            const n = counts[s];
            return (
              <div key={s} className="flex flex-col gap-0.5">
                <div
                  className="font-mono text-[52px] font-medium leading-none tracking-[-0.03em]"
                  style={{ color: n ? meta.color : "#5E6870" }}
                >
                  {n}
                </div>
                <div className="flex items-center gap-2 text-[14px]">
                  <SeverityGlyph severity={s} />
                  <span className="font-mono" style={{ color: meta.color }}>
                    {s}
                  </span>
                </div>
              </div>
            );
          })}
          <div className="grow" />
          <p className="m-0 max-w-[340px] text-right text-[13px] text-muted">
            One block per finding, most severe first.
          </p>
        </div>
        {strip.length > 0 && (
          <nav aria-label="Findings by severity" className="flex h-2.5 gap-[3px]">
            {strip.map((f) => (
              <span
                key={f.finding_id}
                className="min-w-0 flex-1"
                style={{ background: SEVERITY_META[severityOf(f)].color }}
                title={`${severityOf(f)} · ${f.title}`}
              />
            ))}
          </nav>
        )}
      </section>

      {/* triage summary */}
      <section className="flex flex-col gap-2.5 px-6 pt-8">
        <div className="flex items-baseline gap-3">
          <h2 className="m-0 text-[15px] font-semibold">Triage summary</h2>
          <span className="text-[13px] text-muted">
            Written by the model from scanner output. Severities are the scanners' own.
          </span>
        </div>
        <p className="m-0 max-w-[820px] text-[15.5px] leading-[1.6] text-text2">
          {report.executiveSummary}
        </p>
      </section>

      {/* findings */}
      <section aria-labelledby="findings-h" className="flex flex-col pb-8 pt-10">
        <div className="flex items-center gap-5 px-6 pb-4">
          <h2 id="findings-h" className="m-0 text-[20px] font-semibold tracking-[-0.01em]">
            Findings
          </h2>
          <div className="flex gap-1.5">
            {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
              <span
                key={s}
                className="flex h-[26px] items-center gap-1.5 rounded border border-edge px-2.5 text-[12.5px]"
              >
                <SeverityGlyph severity={s} size={10} />
                {s}
                <span className="font-mono text-muted">{counts[s]}</span>
              </span>
            ))}
          </div>
          <div className="grow" />
          <span className="text-[13px] text-muted">Grouped by category</span>
        </div>

        {allFindings.length === 0 ? (
          <p className="px-6 text-[14px] text-muted">
            No findings above the severity floor.
          </p>
        ) : (
          <>
            <div
              aria-hidden
              className="grid grid-cols-[104px_minmax(0,1fr)_170px_84px_110px_16px] gap-4 border-t border-line px-5 py-2 text-[12px] text-muted"
            >
              <span>Severity</span>
              <span>Finding</span>
              <span>Location</span>
              <span>Scanner</span>
              <span>Triage</span>
              <span />
            </div>
            {report.categories.map((group) => (
              <div key={group.category} className="flex flex-col">
                <div className="flex items-baseline gap-3 border-y border-line bg-panel2 px-5 py-2.5">
                  <h3 className="m-0 text-[14px] font-semibold capitalize">{group.category}</h3>
                  <span className="font-mono text-[12.5px] text-muted">
                    {group.findings.length}{" "}
                    {group.findings.length === 1 ? "finding" : "findings"}
                  </span>
                </div>
                {group.findings.map((f) => (
                  <FindingCard key={f.finding_id} finding={f} />
                ))}
              </div>
            ))}
          </>
        )}
      </section>

      {report.checks.length > 0 && <ChecksTable checks={report.checks} />}
    </div>
  );
}
