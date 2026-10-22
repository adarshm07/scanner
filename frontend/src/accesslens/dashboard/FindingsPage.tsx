import { useMemo } from "react";
import { SeverityGlyph } from "../../components/Severity";
import type { DashboardData, Filters } from "./data";
import { RULE_LABEL, teamOf, useFiltered } from "./data";
import { Chip, Empty, FilterBar, Panel, Table, userLink } from "./ui";

/** Every access finding, filterable by rule (from the URL: #findings/RULE). */
export function FindingsPage({
  data,
  filters,
  setFilters,
  rule,
  go,
}: {
  data: DashboardData;
  filters: Filters;
  setFilters: (f: Filters) => void;
  rule: string | null;
  go: (hash: string) => void;
}) {
  const v = useFiltered(data, filters)!;
  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of v.findings) m.set(f.rule, (m.get(f.rule) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [v]);
  const rows = useMemo(
    () => v.findings.filter((f) => !rule || f.rule === rule).sort((a, b) => b.riskScore - a.riskScore),
    [v, rule]
  );

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="m-0 text-[24px] font-semibold tracking-[-0.02em]">Findings</h1>
          <p className="m-0 mt-1 text-[13px] text-muted">Every access issue the rules found, highest risk first.</p>
        </div>
        <FilterBar data={data} value={filters} onChange={setFilters} show={["team", "department", "status", "employeeType", "app"]} />
        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => go("#findings")}
            aria-pressed={!rule}
            className={`rounded-[3px] px-2.5 py-1 text-[12px] ${!rule ? "bg-ink3 text-ink" : "border border-edge text-text3 hover:bg-hover"}`}
          >
            All <span className="font-mono opacity-70">{v.findings.length}</span>
          </button>
          {counts.map(([r, n]) => (
            <button
              key={r}
              onClick={() => go(`#findings/${r}`)}
              aria-pressed={rule === r}
              className={`rounded-[3px] px-2.5 py-1 text-[12px] ${rule === r ? "bg-ink3 text-ink" : "border border-edge text-text3 hover:bg-hover"}`}
            >
              {RULE_LABEL[r] ?? r} <span className="font-mono opacity-70">{n}</span>
            </button>
          ))}
        </div>
      </div>

      <Panel title={rule ? RULE_LABEL[rule] ?? rule : "All findings"} subtitle={`${rows.length} findings`}>
        {rows.length === 0 ? (
          <Empty />
        ) : (
          <Table head={[{ label: "User" }, { label: "Team" }, { label: "App" }, { label: "Issue" }, { label: "Why" }, { label: "Risk", right: true }]}>
            {rows.map((f, i) => {
              const u = v.userById.get(f.userId)!;
              const app = f.appKey ? v.appByKey.get(f.appKey) : undefined;
              return (
                <tr key={i} className="border-b border-line2 align-top">
                  <td className="px-2 py-2">
                    <a href={userLink(u.id)} className="font-medium text-ink3 no-underline hover:underline">
                      {u.name}
                    </a>
                  </td>
                  <td className="px-2 py-2 text-text3">{teamOf(u)}</td>
                  <td className="px-2 py-2">
                    {app ? (
                      <span className="flex items-center gap-2 whitespace-nowrap">
                        <SeverityGlyph severity={app.sensitivity} size={11} />
                        <span className="text-text3">{app.label}</span>
                      </span>
                    ) : (
                      <span className="text-dim">—</span>
                    )}
                  </td>
                  <td className="px-2 py-2">
                    <Chip tone={f.rule === "MISSING_ACCESS" ? "plain" : "warn"}>{RULE_LABEL[f.rule] ?? f.rule}</Chip>
                  </td>
                  <td className="max-w-[420px] px-2 py-2 text-[12px] leading-snug text-muted">{f.explanation}</td>
                  <td className="px-2 py-2 text-right font-mono text-text3">{f.riskScore || "—"}</td>
                </tr>
              );
            })}
          </Table>
        )}
      </Panel>
    </div>
  );
}
