import type { CheckResult, Severity } from "../types";
import { SeverityGlyph } from "./Severity";

/**
 * Domain report "Checks" table — findings first, then passes, with the observed
 * value. Groups by check category (TLS, HTTP headers, Email auth, …).
 */
export function ChecksTable({ checks }: { checks: CheckResult[] }) {
  if (checks.length === 0) return null;

  const groups = new Map<string, CheckResult[]>();
  for (const c of checks) {
    const list = groups.get(c.group) ?? [];
    list.push(c);
    groups.set(c.group, list);
  }
  // Findings first within each group, then passes.
  for (const list of groups.values()) {
    list.sort((a, b) => (a.result === b.result ? 0 : a.result === "finding" ? -1 : 1));
  }
  // Groups with findings first.
  const ordered = [...groups.entries()].sort((a, b) => {
    const fa = a[1].some((c) => c.result === "finding") ? 0 : 1;
    const fb = b[1].some((c) => c.result === "finding") ? 0 : 1;
    return fa - fb;
  });

  const totalFindings = checks.filter((c) => c.result === "finding").length;
  const totalPass = checks.length - totalFindings;

  return (
    <section aria-labelledby="checks-h" className="flex flex-col pt-8">
      <div className="flex items-baseline gap-3 px-6 pb-3">
        <h2 id="checks-h" className="m-0 text-[20px] font-semibold tracking-[-0.01em]">
          Checks
        </h2>
        <span className="text-[13px] text-muted">
          Findings first, then passes with the value observed
        </span>
      </div>

      <div
        aria-hidden
        className="grid grid-cols-[110px_200px_minmax(0,1fr)_110px] gap-4 border-t border-line px-6 py-2 text-[12px] text-muted"
      >
        <span>Result</span>
        <span>Check</span>
        <span>Observed</span>
        <span className="text-right">Source</span>
      </div>

      {ordered.map(([group, rows]) => {
        const findings = rows.filter((r) => r.result === "finding").length;
        const passes = rows.length - findings;
        return (
          <div key={group} className="flex flex-col">
            <div className="flex items-baseline gap-3 border-y border-line bg-panel2 px-6 py-2.5">
              <h3 className="m-0 text-[14px] font-semibold">{group}</h3>
              <span className="font-mono text-[12.5px] text-muted">
                {findings > 0 && `${findings} ${findings === 1 ? "finding" : "findings"}`}
                {findings > 0 && passes > 0 && ", "}
                {passes > 0 && `${passes} passed`}
              </span>
            </div>
            {rows.map((r, i) => (
              <div
                key={`${group}-${r.name}-${i}`}
                className="grid grid-cols-[110px_200px_minmax(0,1fr)_110px] items-start gap-4 border-b border-line2 px-6 py-2.5"
              >
                <span className="flex items-center gap-2">
                  {r.result === "pass" ? (
                    <>
                      <svg width={12} height={12} viewBox="0 0 12 12" aria-hidden="true">
                        <path d="M2.5 6.5 L5 9 L9.5 3.5" fill="none" stroke="#56B982" strokeWidth={1.8} />
                      </svg>
                      <span className="font-mono text-[13px] text-[#56B982]">pass</span>
                    </>
                  ) : (
                    <>
                      <SeverityGlyph severity={(r.severity ?? "low") as Severity} />
                      <span className="font-mono text-[13px] text-sev-low">
                        {r.severity ?? "low"}
                      </span>
                    </>
                  )}
                </span>
                <span className="text-[13.5px] font-medium">{r.name}</span>
                <span className="flex flex-col gap-0.5">
                  <span className="break-words font-mono text-[12.5px] text-text3">{r.observed}</span>
                  {r.remediation && (
                    <span className="text-[12.5px] text-muted">{r.remediation}</span>
                  )}
                </span>
                <span className="text-right font-mono text-[12.5px] text-muted">{r.source}</span>
              </div>
            ))}
          </div>
        );
      })}

      <p className="px-6 pt-3 text-[12.5px] text-muted">
        {totalPass} passed · {totalFindings} {totalFindings === 1 ? "finding" : "findings"}
      </p>
    </section>
  );
}
