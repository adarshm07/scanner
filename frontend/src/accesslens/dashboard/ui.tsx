import type { ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DashboardData, Filters } from "./data";
import { DEFAULT_FILTERS, options } from "./data";

/** Chart roles, validated against the dark panel surface (#12171a). */
export const VIZ = {
  series1: "#3987e5", // blue: primary single series, group grants
  series2: "#d95926", // orange: second series, direct grants
  grid: "#1f252a",
  axis: "#5e6870",
  text: "#c9d0d5",
  muted: "#8d979f",
  surface: "#12171a",
};

export function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`flex min-w-0 flex-col rounded border border-line bg-panel/40 ${className}`}>
      <header className="flex items-start justify-between gap-3 border-b border-line2 px-4 py-3">
        <div className="min-w-0">
          <h2 className="m-0 text-[14px] font-semibold text-ink3">{title}</h2>
          {subtitle && <p className="m-0 mt-0.5 text-[12px] text-muted">{subtitle}</p>}
        </div>
        {action}
      </header>
      <div className="min-w-0 flex-1 p-4">{children}</div>
    </section>
  );
}

export function KpiTile({
  label,
  value,
  detail,
  tone = "plain",
  onClick,
}: {
  label: string;
  value: number | string;
  detail?: string;
  tone?: "plain" | "warn" | "bad";
  onClick?: () => void;
}) {
  const accent = tone === "bad" ? "border-l-[#f0506e]" : tone === "warn" ? "border-l-[#d9b53c]" : "border-l-edge";
  const Tag = onClick ? "button" : "div";
  return (
    <Tag
      onClick={onClick}
      className={`flex min-w-0 flex-col gap-1 rounded border border-line border-l-2 ${accent} bg-panel/40 px-4 py-3 text-left ${
        onClick ? "cursor-pointer hover:bg-hover" : ""
      }`}
    >
      <span className="text-[12px] text-muted">{label}</span>
      <span className="text-[26px] font-semibold leading-none tracking-[-0.02em] text-ink3 tabular-nums">{value}</span>
      {detail && <span className="text-[12px] text-dim">{detail}</span>}
    </Tag>
  );
}

function Select({
  label,
  value,
  onChange,
  items,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  items: [string, string][];
}) {
  return (
    <label className="flex min-w-0 flex-col gap-1 text-[11px] uppercase tracking-wide text-dim">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-[32px] min-w-[140px] rounded border border-edge bg-ink2 px-2 text-[13px] normal-case tracking-normal text-ink3 outline-hidden focus:border-muted"
      >
        {items.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </label>
  );
}

/** One row of filters above all charts. */
export function FilterBar({
  data,
  value,
  onChange,
  show = ["team", "department", "status", "employeeType", "app", "inactiveDays"],
}: {
  data: DashboardData;
  value: Filters;
  onChange: (f: Filters) => void;
  show?: (keyof Filters)[];
}) {
  const o = options(data);
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => onChange({ ...value, [k]: v });
  const all = (xs: string[], label: string): [string, string][] => [["all", label], ...xs.map((x): [string, string] => [x, x])];
  const dirty = JSON.stringify(value) !== JSON.stringify(DEFAULT_FILTERS);
  return (
    <div className="flex flex-wrap items-end gap-3">
      {show.includes("team") && <Select label="Team" value={value.team} onChange={(v) => set("team", v)} items={all(o.teams, "All teams")} />}
      {show.includes("department") && (
        <Select label="Department" value={value.department} onChange={(v) => set("department", v)} items={all(o.departments, "All departments")} />
      )}
      {show.includes("status") && (
        <Select
          label="Status"
          value={value.status}
          onChange={(v) => set("status", v as Filters["status"])}
          items={[
            ["all", "All statuses"],
            ["active", "Active"],
            ["inactive", "Inactive / deprovisioned"],
          ]}
        />
      )}
      {show.includes("employeeType") && (
        <Select label="Type" value={value.employeeType} onChange={(v) => set("employeeType", v)} items={all(o.employeeTypes, "All types")} />
      )}
      {show.includes("app") && (
        <Select
          label="App"
          value={value.app}
          onChange={(v) => set("app", v)}
          items={[["all", "All apps"], ...[...data.apps].sort((a, b) => a.label.localeCompare(b.label)).map((a): [string, string] => [a.key, a.label])]}
        />
      )}
      {show.includes("inactiveDays") && (
        <Select
          label="Not used for"
          value={String(value.inactiveDays)}
          onChange={(v) => set("inactiveDays", Number(v))}
          items={[
            ["30", "30+ days"],
            ["60", "60+ days"],
            ["90", "90+ days"],
          ]}
        />
      )}
      {dirty && (
        <button onClick={() => onChange(DEFAULT_FILTERS)} className="h-[32px] rounded px-2.5 text-[12px] text-muted hover:bg-hover hover:text-ink3">
          Reset filters
        </button>
      )}
    </div>
  );
}

function ChartTip({ active, payload, label, unit }: { active?: boolean; payload?: { name?: string; value?: number; color?: string }[]; label?: string; unit: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded border border-edge bg-ink2 px-2.5 py-1.5 text-[12px] shadow-lg">
      <div className="mb-0.5 font-medium text-ink3">{label}</div>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2 text-text3">
          {payload.length > 1 && <span className="inline-block h-2 w-2 rounded-sm" style={{ background: p.color }} />}
          <span className="tabular-nums">{p.value}</span>
          <span className="text-muted">{payload.length > 1 ? p.name : unit}</span>
        </div>
      ))}
    </div>
  );
}

export interface BarDatum {
  key: string;
  label: string;
  [series: string]: string | number;
}

/**
 * Horizontal bar chart: one or two series (stacked), labels on the y axis, hover tooltip,
 * and an optional click per bar. Rows are sized so long labels stay readable.
 */
export function HBar({
  data,
  series,
  unit,
  onSelect,
  selected,
  labelWidth = 130,
  showValues = false,
}: {
  data: BarDatum[];
  series: { key: string; name: string; color: string }[];
  unit: string;
  onSelect?: (key: string) => void;
  selected?: string | null;
  labelWidth?: number;
  /** Print each bar's value at its end (single series only; use for short charts). */
  showValues?: boolean;
}) {
  if (data.length === 0) return <Empty />;
  const height = Math.max(120, data.length * 30 + 30);
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: showValues ? 40 : 16, bottom: 0, left: 0 }} barCategoryGap={8}>
          <CartesianGrid horizontal={false} stroke={VIZ.grid} />
          <XAxis type="number" allowDecimals={false} stroke={VIZ.axis} tick={{ fill: VIZ.muted, fontSize: 11 }} tickLine={false} axisLine={false} />
          <YAxis
            type="category"
            dataKey="label"
            width={labelWidth}
            stroke={VIZ.axis}
            tick={{ fill: VIZ.text, fontSize: 12 }}
            tickLine={false}
            axisLine={false}
            interval={0}
          />
          <Tooltip cursor={{ fill: "#ffffff0a" }} content={<ChartTip unit={unit} />} />
          {series.map((s, i) => (
            <Bar
              key={s.key}
              dataKey={s.key}
              name={s.name}
              stackId="a"
              fill={s.color}
              stroke={VIZ.surface}
              strokeWidth={series.length > 1 ? 1 : 0}
              radius={i === series.length - 1 ? [0, 4, 4, 0] : 0}
              maxBarSize={18}
              cursor={onSelect ? "pointer" : undefined}
              onClick={onSelect ? (d: { payload?: BarDatum }) => d.payload && onSelect(d.payload.key) : undefined}
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.key} fillOpacity={selected && selected !== d.key ? 0.35 : 1} />
              ))}
              {showValues && series.length === 1 && (
                <LabelList dataKey={s.key} position="right" fill={VIZ.text} fontSize={12} className="tabular-nums" />
              )}
            </Bar>
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function Legend({ items }: { items: { name: string; color: string }[] }) {
  return (
    <div className="flex flex-wrap gap-3 text-[12px] text-muted">
      {items.map((i) => (
        <span key={i.name} className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: i.color }} />
          {i.name}
        </span>
      ))}
    </div>
  );
}

export function Empty({ children = "Nothing matches these filters." }: { children?: ReactNode }) {
  return <div className="py-6 text-center text-[13px] text-muted">{children}</div>;
}

export function Table({ head, children }: { head: { label: string; right?: boolean }[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-dim">
            {head.map((h) => (
              <th key={h.label} className={`px-2 py-1.5 font-medium ${h.right ? "text-right" : ""}`}>
                {h.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Chip({ children, tone = "plain" }: { children: ReactNode; tone?: "plain" | "warn" | "bad" }) {
  const cls =
    tone === "bad"
      ? "border-[#8a2f40] text-[#f58aa0]"
      : tone === "warn"
        ? "border-[#7a6420] text-[#e8c45a]"
        : "border-edge text-text3";
  return <span className={`inline-flex items-center whitespace-nowrap rounded-[3px] border px-1.5 py-0.5 text-[11px] ${cls}`}>{children}</span>;
}

export const userLink = (id: number) => `#users/${id}`;
