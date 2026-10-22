import { useMemo, useState } from "react";
import { SEVERITY_META, SeverityGlyph } from "../../components/Severity";
import type { DashboardData, Filters } from "./data";
import { isInactive, teamOf, useFiltered } from "./data";
import { Chip, FilterBar, HBar, Legend, Panel, Table, VIZ, userLink } from "./ui";

/** Per-app view: holders, unused access, direct grants and findings. */
export function AppsPage({ data, filters, setFilters }: { data: DashboardData; filters: Filters; setFilters: (f: Filters) => void }) {
  const v = useFiltered(data, { ...filters, app: "all" })!;
  const [open, setOpen] = useState<string | null>(null);
  const days = filters.inactiveDays;

  const rows = useMemo(
    () =>
      data.apps
        .map((app) => {
          const held = v.assignments.filter((a) => a.appKey === app.key);
          return {
            app,
            held,
            unused: held.filter((a) => isInactive(a, days)).length,
            never: held.filter((a) => a.daysSinceUse == null).length,
            direct: held.filter((a) => a.source === "DIRECT").length,
            findings: v.findings.filter((f) => f.appKey === app.key && f.rule !== "MISSING_ACCESS").length,
            missing: v.findings.filter((f) => f.appKey === app.key && f.rule === "MISSING_ACCESS").length,
          };
        })
        .sort((a, b) => SEVERITY_META[a.app.sensitivity].rank - SEVERITY_META[b.app.sensitivity].rank || b.held.length - a.held.length),
    [data.apps, v, days]
  );

  const grantChart = rows
    .filter((r) => r.held.length > 0)
    .sort((a, b) => b.held.length - a.held.length)
    .map((r) => ({ key: r.app.key, label: r.app.label, group: r.held.length - r.direct, direct: r.direct }));

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="m-0 text-[24px] font-semibold tracking-[-0.02em]">Apps</h1>
          <p className="m-0 mt-1 text-[13px] text-muted">Who holds each app, whether they use it, and how it was granted. Click a row to see holders.</p>
        </div>
        <FilterBar data={data} value={filters} onChange={setFilters} show={["team", "department", "status", "employeeType", "inactiveDays"]} />
      </div>

      <Panel title="Apps" subtitle={`${rows.length} apps, most sensitive first`}>
        <Table
          head={[
            { label: "App" },
            { label: "Holders", right: true },
            { label: `Not used ${days}d+`, right: true },
            { label: "Never used", right: true },
            { label: "Direct grants", right: true },
            { label: "Findings", right: true },
            { label: "Missing for", right: true },
          ]}
        >
          {rows.map((r) => (
            <FragmentRow key={r.app.key} r={r} open={open === r.app.key} onToggle={() => setOpen(open === r.app.key ? null : r.app.key)} data={data} days={days} v={v} />
          ))}
        </Table>
      </Panel>

      <Panel title="How access was granted" subtitle="Group-based vs direct assignments per app. Direct grants bypass group policy.">
        <HBar
          data={grantChart}
          series={[
            { key: "group", name: "Via group", color: VIZ.series1 },
            { key: "direct", name: "Direct", color: VIZ.series2 },
          ]}
          unit="assignments"
          labelWidth={150}
        />
        <div className="mt-3">
          <Legend
            items={[
              { name: "Via group", color: VIZ.series1 },
              { name: "Direct", color: VIZ.series2 },
            ]}
          />
        </div>
      </Panel>
    </div>
  );
}

type Row = {
  app: DashboardData["apps"][number];
  held: DashboardData["assignments"];
  unused: number;
  never: number;
  direct: number;
  findings: number;
  missing: number;
};

function FragmentRow({
  r,
  open,
  onToggle,
  v,
  days,
}: {
  r: Row;
  open: boolean;
  onToggle: () => void;
  data: DashboardData;
  days: number;
  v: NonNullable<ReturnType<typeof useFiltered>>;
}) {
  const num = (n: number, warn = false) => (
    <td className={`px-2 py-2 text-right font-mono ${n > 0 && warn ? "text-[#e8c45a]" : n > 0 ? "text-text3" : "text-dim"}`}>{n}</td>
  );
  return (
    <>
      <tr onClick={onToggle} className={`cursor-pointer border-b border-line2 hover:bg-hover ${open ? "bg-hover" : ""}`}>
        <td className="px-2 py-2">
          <span className="flex items-center gap-2">
            <span className="w-3 font-mono text-[11px] text-dim">{open ? "▾" : "▸"}</span>
            <SeverityGlyph severity={r.app.sensitivity} size={11} />
            <span className="font-medium text-ink3">{r.app.label}</span>
            <span className="font-mono text-[11px] text-dim">{r.app.sensitivity}</span>
          </span>
        </td>
        {num(r.held.length)}
        {num(r.unused, true)}
        {num(r.never, true)}
        {num(r.direct, true)}
        {num(r.findings, true)}
        {num(r.missing)}
      </tr>
      {open && (
        <tr className="border-b border-line2 bg-ink2/60">
          <td colSpan={7} className="px-4 py-3">
            {r.held.length === 0 ? (
              <span className="text-[13px] text-muted">No holders for these filters.</span>
            ) : (
              <div className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-[13px] md:grid-cols-2 xl:grid-cols-3">
                {[...r.held]
                  .sort((a, b) => (b.daysSinceUse ?? 1e9) - (a.daysSinceUse ?? 1e9))
                  .map((a) => {
                    const u = v.userById.get(a.userId)!;
                    const stale = a.daysSinceUse == null || a.daysSinceUse >= days;
                    return (
                      <div key={a.userId} className="flex min-w-0 items-center gap-2">
                        <a href={userLink(u.id)} className="truncate text-ink3 no-underline hover:underline">
                          {u.name}
                        </a>
                        <span className="truncate text-[12px] text-muted">{teamOf(u)}</span>
                        <span className={`ml-auto whitespace-nowrap font-mono text-[11px] ${stale ? "text-[#f58aa0]" : "text-dim"}`}>
                          {a.daysSinceUse == null ? "never" : `${a.daysSinceUse}d`}
                        </span>
                        {a.source === "DIRECT" && <Chip tone="warn">direct</Chip>}
                      </div>
                    );
                  })}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
