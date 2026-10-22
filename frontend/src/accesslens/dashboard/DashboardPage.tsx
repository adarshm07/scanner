import { useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITY_META, SEVERITY_ORDER, SeverityGlyph } from "../../components/Severity";
import type { Severity } from "../../types";
import type { DashboardData, Filters } from "./data";
import { RULE_LABEL, daysBefore, isInactive, teamOf, useFiltered } from "./data";
import { Chip, Empty, FilterBar, HBar, KpiTile, Legend, Panel, Table, VIZ, userLink } from "./ui";

/** Risk score at or above which a user counts as high risk on the dashboard. */
export const HIGH_RISK = 10;
const NEW_USER_DAYS = 7;

function ago(days: number | null) {
  if (days == null) return "never";
  if (days === 0) return "today";
  return days < 60 ? `${days}d ago` : `${Math.round(days / 30)}mo ago`;
}

export function DashboardPage({
  data,
  filters,
  setFilters,
  go,
}: {
  data: DashboardData;
  filters: Filters;
  setFilters: (f: Filters) => void;
  go: (hash: string) => void;
}) {
  const v = useFiltered(data, filters)!;
  const [pickedApp, setPickedApp] = useState<string | null>(null);
  const days = filters.inactiveDays;

  const m = useMemo(() => {
    const flagged = v.users.filter((u) => u.findingCount > 0);
    const active = v.users.filter((u) => u.status === "ACTIVE");
    const age = (iso: string | null) => daysBefore(data.asOf, iso);
    const newUsers = v.users
      .filter((u) => {
        const a = age(u.created);
        return a != null && a < 30;
      })
      .sort((a, b) => (age(a.created) ?? 0) - (age(b.created) ?? 0));
    const inactive = v.assignments.filter((a) => isInactive(a, days));
    const inactiveUsers = new Set(inactive.map((a) => a.userId));

    // Access issues by rule
    const byRule = new Map<string, number>();
    for (const f of v.findings) byRule.set(f.rule, (byRule.get(f.rule) ?? 0) + 1);
    const rules = [...byRule.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([rule, n]) => ({ key: rule, label: RULE_LABEL[rule] ?? rule, findings: n }));

    // Users not using each app for N+ days
    const perApp = new Map<string, number>();
    for (const a of inactive) perApp.set(a.appKey, (perApp.get(a.appKey) ?? 0) + 1);
    const unusedByApp = [...perApp.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([key, n]) => ({ key, label: v.appByKey.get(key)?.label ?? key, users: n }));

    // Flagged vs clean users per team
    const teams = new Map<string, { flagged: number; clean: number }>();
    for (const u of v.users) {
      const t = teams.get(teamOf(u)) ?? { flagged: 0, clean: 0 };
      u.findingCount > 0 ? t.flagged++ : t.clean++;
      teams.set(teamOf(u), t);
    }
    const byTeam = [...teams.entries()]
      .sort((a, b) => b[1].flagged - a[1].flagged || b[1].clean - a[1].clean)
      .map(([team, t]) => ({ key: team, label: team, ...t }));

    // Findings by app sensitivity (app-level findings only)
    const bySens = new Map<Severity, number>();
    for (const f of v.findings) {
      const s = f.appKey ? v.appByKey.get(f.appKey)?.sensitivity : undefined;
      if (s) bySens.set(s, (bySens.get(s) ?? 0) + 1);
    }
    const sensitivity = SEVERITY_ORDER.map((s) => ({ key: s, label: s, findings: bySens.get(s) ?? 0 }));

    // How long since each assignment was used
    const buckets = [
      { key: "7", label: "≤ 7 days", test: (d: number | null) => d != null && d <= 7 },
      { key: "30", label: "8–30 days", test: (d: number | null) => d != null && d > 7 && d <= 30 },
      { key: "90", label: "31–90 days", test: (d: number | null) => d != null && d > 30 && d <= 90 },
      { key: "90+", label: "90+ days", test: (d: number | null) => d != null && d > 90 },
      { key: "never", label: "Never used", test: (d: number | null) => d == null },
    ].map((b) => ({ key: b.key, label: b.label, assignments: v.assignments.filter((a) => b.test(a.daysSinceUse)).length }));

    const topRisk = [...v.users].filter((u) => u.riskScore > 0).sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);

    const sensitiveUnused = inactive
      .filter((a) => {
        const s = v.appByKey.get(a.appKey)?.sensitivity;
        return s === "critical" || s === "high";
      })
      .sort(
        (a, b) =>
          SEVERITY_META[v.appByKey.get(a.appKey)!.sensitivity].rank - SEVERITY_META[v.appByKey.get(b.appKey)!.sensitivity].rank ||
          (b.daysSinceUse ?? 1e9) - (a.daysSinceUse ?? 1e9)
      );

    const sod = v.findings.filter((f) => f.rule === "TOXIC_COMBINATION");
    const contractors = v.users
      .filter((u) => u.employeeType === "Contractor")
      .map((u) => ({
        u,
        sensitive: v.assignments
          .filter((a) => a.userId === u.id)
          .map((a) => v.appByKey.get(a.appKey)!)
          .filter((app) => app && (app.sensitivity === "critical" || app.sensitivity === "high")),
      }))
      .filter((c) => c.sensitive.length > 0);

    const reviewed = v.users.filter((u) => u.review);
    const verdicts = reviewed.reduce(
      (s, u) => ({ keep: s.keep + u.review!.keep, review: s.review + u.review!.review, revoke: s.revoke + u.review!.revoke }),
      { keep: 0, review: 0, revoke: 0 }
    );

    return {
      flagged,
      active,
      newUsers,
      new7: newUsers.filter((u) => (age(u.created) ?? 99) < NEW_USER_DAYS),
      inactive,
      inactiveUsers,
      rules,
      unusedByApp,
      byTeam,
      sensitivity,
      buckets,
      topRisk,
      sensitiveUnused,
      sod,
      contractors,
      reviewed,
      verdicts,
      apps: new Set(v.assignments.map((a) => a.appKey)).size,
    };
  }, [v, days, data.asOf]);

  const pickedRows = pickedApp
    ? m.inactive
        .filter((a) => a.appKey === pickedApp)
        .sort((a, b) => (b.daysSinceUse ?? 1e9) - (a.daysSinceUse ?? 1e9))
    : [];
  const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "—");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="m-0 text-[24px] font-semibold tracking-[-0.02em]">Access dashboard</h1>
          <p className="m-0 mt-1 text-[13px] text-muted">
            Okta workforce access at a glance. Day counts are measured from the last sync ({data.asOf.slice(0, 10)}).
          </p>
        </div>
        <FilterBar data={data} value={filters} onChange={setFilters} />
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiTile label="Users" value={v.users.length} detail={`${m.active.length} active · ${v.users.length - m.active.length} inactive`} onClick={() => go("#users")} />
        <KpiTile
          label="Flagged users"
          value={m.flagged.length}
          detail={`${pct(m.flagged.length, v.users.length)} of users have at least one issue`}
          tone={m.flagged.length ? "warn" : "plain"}
          onClick={() => go("#users")}
        />
        <KpiTile
          label={`New users (< ${NEW_USER_DAYS} days)`}
          value={m.new7.length}
          detail={`${m.newUsers.length} joined in the last 30 days`}
        />
        <KpiTile label="High-risk users" value={v.users.filter((u) => u.riskScore >= HIGH_RISK).length} detail={`risk score ${HIGH_RISK}+`} tone="bad" />
        <KpiTile label="Apps" value={m.apps} detail={`of ${data.apps.length} in the tenant`} onClick={() => go("#apps")} />
        <KpiTile label="Assignments" value={v.assignments.length} detail={`${v.assignments.filter((a) => a.source === "DIRECT").length} granted directly`} />
        <KpiTile
          label={`Not used for ${days}+ days`}
          value={m.inactive.length}
          detail={`assignments held by ${m.inactiveUsers.size} users`}
          tone={m.inactive.length ? "warn" : "plain"}
        />
        <KpiTile
          label="Privileged users"
          value={v.users.filter((u) => u.adminRoles.length > 0).length}
          detail="hold an Okta admin role"
          onClick={() => go("#findings/PRIVILEGED_ROLE")}
        />
      </div>

      {/* Main charts */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Access issues found" subtitle="Findings by type. Click a bar to open those findings.">
          <HBar data={m.rules} series={[{ key: "findings", name: "Findings", color: VIZ.series1 }]} unit="findings" onSelect={(k) => go(`#findings/${k}`)} />
        </Panel>
        <Panel
          title={`Users not using an app for ${days}+ days`}
          subtitle="Holders who haven't signed in to the app since, including never. Click a bar to list them."
        >
          <HBar
            data={m.unusedByApp}
            series={[{ key: "users", name: "Users", color: VIZ.series1 }]}
            unit="users"
            onSelect={(k) => setPickedApp(pickedApp === k ? null : k)}
            selected={pickedApp}
          />
        </Panel>
      </div>

      {pickedApp && (
        <Panel
          title={`${pickedRows.length} users didn't use ${v.appByKey.get(pickedApp)?.label ?? pickedApp} for ${days}+ days`}
          action={
            <button onClick={() => setPickedApp(null)} className="rounded px-2 py-1 text-[12px] text-muted hover:bg-hover hover:text-ink3">
              Close
            </button>
          }
        >
          <Table head={[{ label: "User" }, { label: "Team" }, { label: "Last used" }, { label: "Granted" }, { label: "Assigned", right: true }]}>
            {pickedRows.map((a) => {
              const u = v.userById.get(a.userId)!;
              return (
                <tr key={a.userId} className="border-b border-line2">
                  <td className="px-2 py-2">
                    <a href={userLink(u.id)} className="font-medium text-ink3 no-underline hover:underline">
                      {u.name}
                    </a>
                    {u.status !== "ACTIVE" && <span className="ml-2"><Chip tone="bad">{u.status.toLowerCase()}</Chip></span>}
                  </td>
                  <td className="px-2 py-2 text-text3">{teamOf(u)}</td>
                  <td className="px-2 py-2 text-[#f58aa0]">{ago(a.daysSinceUse)}</td>
                  <td className="px-2 py-2 text-text3">{a.source === "DIRECT" ? <Chip tone="warn">direct</Chip> : "via group"}</td>
                  <td className="px-2 py-2 text-right font-mono text-[12px] text-muted">{ago(a.assignedDays)}</td>
                </tr>
              );
            })}
          </Table>
        </Panel>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Flagged users by team" subtitle="Click a team to filter the dashboard.">
          <HBar
            data={m.byTeam}
            series={[
              { key: "flagged", name: "Flagged", color: VIZ.series2 },
              { key: "clean", name: "No issues", color: VIZ.series1 },
            ]}
            unit="users"
            labelWidth={96}
            onSelect={(k) => setFilters({ ...filters, team: filters.team === k ? "all" : k })}
            selected={filters.team === "all" ? null : filters.team}
          />
          <div className="mt-3">
            <Legend
              items={[
                { name: "Flagged", color: VIZ.series2 },
                { name: "No issues", color: VIZ.series1 },
              ]}
            />
          </div>
        </Panel>
        <Panel title="Issues by app sensitivity" subtitle="App-level findings, grouped by how sensitive the app is.">
          <SensitivityChart rows={m.sensitivity} />
        </Panel>
        <Panel title="Time since last use" subtitle="Every assignment, by how long since the user last signed in to it.">
          <HBar data={m.buckets} series={[{ key: "assignments", name: "Assignments", color: VIZ.series1 }]} unit="assignments" labelWidth={86} showValues />
        </Panel>
      </div>

      {/* Lists */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Riskiest users" subtitle="Top 10 by combined risk score.">
          {m.topRisk.length === 0 ? (
            <Empty />
          ) : (
            <Table head={[{ label: "User" }, { label: "Team" }, { label: "Main issues" }, { label: "Risk", right: true }]}>
              {m.topRisk.map((u) => (
                <tr key={u.id} className="border-b border-line2 align-top">
                  <td className="px-2 py-2">
                    <a href={userLink(u.id)} className="font-medium text-ink3 no-underline hover:underline">
                      {u.name}
                    </a>
                    <div className="text-[12px] text-muted">{u.title ?? u.cohort?.label ?? "—"}</div>
                  </td>
                  <td className="px-2 py-2 text-text3">{teamOf(u)}</td>
                  <td className="px-2 py-2">
                    <div className="flex flex-wrap gap-1">
                      {u.topRules.slice(0, 3).map((r) => (
                        <Chip key={r} tone="warn">
                          {RULE_LABEL[r] ?? r}
                        </Chip>
                      ))}
                    </div>
                  </td>
                  <td className={`px-2 py-2 text-right font-mono ${u.riskScore >= HIGH_RISK ? "text-[#f58aa0]" : "text-text3"}`}>{u.riskScore}</td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>

        <Panel title="New joiners" subtitle="Users created in the last 30 days, and the cohort apps they still don't have.">
          {m.newUsers.length === 0 ? (
            <Empty>No one joined in the last 30 days.</Empty>
          ) : (
            <Table head={[{ label: "User" }, { label: "Team" }, { label: "Joined" }, { label: "Apps", right: true }, { label: "Missing", right: true }]}>
              {m.newUsers.map((u) => (
                <tr key={u.id} className="border-b border-line2">
                  <td className="px-2 py-2">
                    <a href={userLink(u.id)} className="font-medium text-ink3 no-underline hover:underline">
                      {u.name}
                    </a>
                    {(daysBefore(data.asOf, u.created) ?? 99) < NEW_USER_DAYS && <span className="ml-2"><Chip>new</Chip></span>}
                  </td>
                  <td className="px-2 py-2 text-text3">{teamOf(u)}</td>
                  <td className="px-2 py-2 text-text3">{ago(daysBefore(data.asOf, u.created))}</td>
                  <td className="px-2 py-2 text-right font-mono text-text3">{u.appCount}</td>
                  <td className="px-2 py-2 text-right font-mono text-text3">
                    {v.findings.filter((f) => f.userId === u.id && f.rule === "MISSING_ACCESS").length}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>

        <Panel title={`Unused sensitive access (${days}+ days)`} subtitle="High and critical apps nobody is using. The quickest revocations.">
          {m.sensitiveUnused.length === 0 ? (
            <Empty />
          ) : (
            <div className="max-h-[360px] overflow-y-auto">
              <Table head={[{ label: "App" }, { label: "User" }, { label: "Last used" }, { label: "Granted" }]}>
                {m.sensitiveUnused.map((a) => {
                  const app = v.appByKey.get(a.appKey)!;
                  const u = v.userById.get(a.userId)!;
                  return (
                    <tr key={`${a.userId}-${a.appKey}`} className="border-b border-line2">
                      <td className="px-2 py-2">
                        <span className="flex items-center gap-2">
                          <SeverityGlyph severity={app.sensitivity} size={11} />
                          <span className="text-ink3">{app.label}</span>
                        </span>
                      </td>
                      <td className="px-2 py-2">
                        <a href={userLink(u.id)} className="text-text3 no-underline hover:underline">
                          {u.name}
                        </a>
                      </td>
                      <td className="px-2 py-2 text-[#f58aa0]">{ago(a.daysSinceUse)}</td>
                      <td className="px-2 py-2 text-text3">{a.source === "DIRECT" ? <Chip tone="warn">direct</Chip> : "via group"}</td>
                    </tr>
                  );
                })}
              </Table>
            </div>
          )}
        </Panel>

        <div className="flex flex-col gap-4">
          <Panel title="Separation-of-duties conflicts" subtitle="Users holding app pairs that shouldn't sit together.">
            {m.sod.length === 0 ? (
              <Empty>No conflicts for these filters.</Empty>
            ) : (
              <ul className="m-0 flex list-none flex-col gap-2 p-0 text-[13px]">
                {m.sod.map((f, i) => {
                  const u = v.userById.get(f.userId)!;
                  return (
                    <li key={i} className="rounded border border-[#8a2f40] bg-[#8a2f40]/10 px-3 py-2">
                      <a href={userLink(u.id)} className="font-medium text-ink3 no-underline hover:underline">
                        {u.name}
                      </a>
                      <span className="text-muted"> · {f.explanation}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>
          <Panel title="Contractors with sensitive access" subtitle="Contractors holding high or critical apps.">
            {m.contractors.length === 0 ? (
              <Empty>None for these filters.</Empty>
            ) : (
              <ul className="m-0 flex list-none flex-col gap-2 p-0 text-[13px]">
                {m.contractors.map(({ u, sensitive }) => (
                  <li key={u.id} className="flex flex-wrap items-center gap-2">
                    <a href={userLink(u.id)} className="min-w-[140px] font-medium text-ink3 no-underline hover:underline">
                      {u.name}
                    </a>
                    {sensitive.map((app) => (
                      <Chip key={app.key} tone={app.sensitivity === "critical" ? "bad" : "warn"}>
                        {app.label}
                      </Chip>
                    ))}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="AI review progress" subtitle="Users whose access has been checked on the Users page.">
            <div className="flex flex-wrap items-end gap-6">
              <div>
                <div className="text-[26px] font-semibold leading-none tabular-nums text-ink3">
                  {m.reviewed.length}
                  <span className="text-[14px] font-normal text-muted"> / {v.users.length}</span>
                </div>
                <div className="mt-1 text-[12px] text-muted">users reviewed</div>
              </div>
              <div className="flex gap-4 font-mono text-[12px] text-muted">
                <span><span className="text-[16px] text-[#7fd1a8]">{m.verdicts.keep}</span> keep</span>
                <span><span className="text-[16px] text-[#e8c45a]">{m.verdicts.review}</span> review</span>
                <span><span className="text-[16px] text-[#f58aa0]">{m.verdicts.revoke}</span> revoke</span>
              </div>
            </div>
            <div className="mt-3 h-1.5 w-full overflow-hidden rounded bg-line">
              <div className="h-full bg-[#3987e5]" style={{ width: pct(m.reviewed.length, v.users.length) === "—" ? 0 : pct(m.reviewed.length, v.users.length) }} />
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

/** Bars colored by the app's own severity language (color + glyph in the axis label). */
function SensitivityChart({ rows }: { rows: { key: Severity; label: string; findings: number }[] }) {
  if (rows.every((r) => r.findings === 0)) return <Empty />;
  return (
    <div style={{ height: 170 }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }} barCategoryGap={8}>
          <CartesianGrid horizontal={false} stroke={VIZ.grid} />
          <XAxis type="number" allowDecimals={false} tick={{ fill: VIZ.muted, fontSize: 11 }} tickLine={false} axisLine={false} />
          <YAxis
            type="category"
            dataKey="key"
            width={86}
            tickLine={false}
            axisLine={false}
            interval={0}
            tick={({ x, y, payload }) => {
              const sev = payload.value as Severity;
              return (
                <g transform={`translate(${Number(x) - 78},${Number(y) - 6})`}>
                  <path d={SEVERITY_META[sev].d} fill={SEVERITY_META[sev].fill} stroke={SEVERITY_META[sev].color} strokeWidth={1.6} />
                  <text x={18} y={10} fill={VIZ.text} fontSize={12}>
                    {sev}
                  </text>
                </g>
              );
            }}
          />
          <Tooltip
            cursor={{ fill: "#ffffff0a" }}
            content={({ active, payload }) =>
              active && payload?.length ? (
                <div className="rounded border border-edge bg-ink2 px-2.5 py-1.5 text-[12px]">
                  <span className="font-medium text-ink3">{String(payload[0].payload.label)}</span>
                  <span className="ml-2 tabular-nums text-text3">{String(payload[0].value)}</span> <span className="text-muted">findings</span>
                </div>
              ) : null
            }
          />
          <Bar dataKey="findings" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false}>
            {rows.map((r) => (
              <Cell key={r.key} fill={SEVERITY_META[r.key].color} />
            ))}
            <LabelList dataKey="findings" position="right" fill={VIZ.text} fontSize={12} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
