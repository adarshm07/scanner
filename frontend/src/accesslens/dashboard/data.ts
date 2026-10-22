import { useCallback, useEffect, useMemo, useState } from "react";
import type { Severity } from "../../types";
import type { AlUserSummary } from "../types";
import { load, save } from "../../lib/storage";

/** Shapes returned by GET /api/accesslens/dashboard. */
export interface DashApp {
  key: string;
  label: string;
  sensitivity: Severity;
}
export interface DashAssignment {
  userId: number;
  appKey: string;
  daysSinceUse: number | null;
  assignedDays: number | null;
  ssoCount90d: number;
  source: "GROUP" | "DIRECT";
  rules: string[];
}
export interface DashFinding {
  userId: number;
  appKey: string | null;
  rule: string;
  riskScore: number;
  explanation: string;
}
export interface DashboardData {
  tenant: { domain: string; lastSyncAt: string | null };
  asOf: string;
  thresholds: { unused_days: number; never_used_days: number };
  apps: DashApp[];
  users: AlUserSummary[];
  assignments: DashAssignment[];
  findings: DashFinding[];
}

export const RULE_LABEL: Record<string, string> = {
  STALE_ACCOUNT: "Stale account",
  UNUSED_ACCESS: "Unused access",
  NEVER_USED: "Never used",
  OUTLIER_ACCESS: "Outlier access",
  MISSING_ACCESS: "Missing access",
  DIRECT_ASSIGNMENT: "Direct grant",
  PRIVILEGED_ROLE: "Privileged role",
  TOXIC_COMBINATION: "SoD conflict",
};

export const NO_TEAM = "Unassigned";
export const teamOf = (u: AlUserSummary) => u.team ?? NO_TEAM;

export interface Filters {
  team: string;
  department: string;
  status: "all" | "active" | "inactive";
  employeeType: string;
  app: string;
  /** "Not used in N days" threshold. */
  inactiveDays: number;
}

export const DEFAULT_FILTERS: Filters = {
  team: "all",
  department: "all",
  status: "all",
  employeeType: "all",
  app: "all",
  inactiveDays: 30,
};

const DAY = 86_400_000;

/** Days between a date and the sync date (day counts follow the last Okta sync). */
export function daysBefore(asOf: string, iso: string | null): number | null {
  if (!iso) return null;
  return Math.max(0, Math.floor((new Date(asOf).getTime() - new Date(iso).getTime()) / DAY));
}

/** True when an assignment hasn't been used within the threshold (never used counts). */
export function isInactive(a: DashAssignment, days: number) {
  return a.daysSinceUse == null || a.daysSinceUse >= days;
}

const DASH_CACHE = "cache/dashboard";

/**
 * Dashboard payload, shown from the browser cache first and then refreshed from the backend.
 * `savedAt` is set while the cached copy is what's on screen; `error` is set if the refresh
 * failed (the cached data, if any, stays visible).
 */
export function useDashboardData() {
  const [cached] = useState(() => load<DashboardData>(DASH_CACHE));
  const [data, setData] = useState<DashboardData | null>(cached?.value ?? null);
  const [savedAt, setSavedAt] = useState<string | null>(cached?.savedAt ?? null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  useEffect(() => {
    fetch("/api/accesslens/dashboard")
      .then(async (r) => {
        const d = await r.json();
        if (!r.ok) throw new Error(d.error ?? "Dashboard data failed to load");
        setData(d);
        setSavedAt(null);
        setError(null);
        save(DASH_CACHE, d);
      })
      .catch((e) => setError((e as Error).message || "Backend not reachable. Start it with `npm run dev` in backend/."));
  }, [version]);
  /** Re-fetch, e.g. after a scan refreshed the data and AI reviews. */
  const reload = useCallback(() => setVersion((v) => v + 1), []);
  return { data, error, savedAt, reload };
}

/** Applies the filter row. App filter narrows assignments and findings, not users. */
export function useFiltered(data: DashboardData | null, f: Filters) {
  return useMemo(() => {
    if (!data) return null;
    const users = data.users.filter(
      (u) =>
        (f.team === "all" || teamOf(u) === f.team) &&
        (f.department === "all" || (u.department ?? NO_TEAM) === f.department) &&
        (f.status === "all" || (f.status === "active") === (u.status === "ACTIVE")) &&
        (f.employeeType === "all" || u.employeeType === f.employeeType)
    );
    const ids = new Set(users.map((u) => u.id));
    const assignments = data.assignments.filter((a) => ids.has(a.userId) && (f.app === "all" || a.appKey === f.app));
    const findings = data.findings.filter(
      (x) => ids.has(x.userId) && (f.app === "all" || x.appKey === f.app)
    );
    const userById = new Map(data.users.map((u) => [u.id, u]));
    const appByKey = new Map(data.apps.map((a) => [a.key, a]));
    return { users, assignments, findings, userById, appByKey };
  }, [data, f]);
}

export function options(data: DashboardData) {
  const uniq = (xs: string[]) => [...new Set(xs)].sort((a, b) => (a === NO_TEAM ? 1 : b === NO_TEAM ? -1 : a.localeCompare(b)));
  return {
    teams: uniq(data.users.map(teamOf)),
    departments: uniq(data.users.map((u) => u.department ?? NO_TEAM)),
    employeeTypes: uniq(data.users.map((u) => u.employeeType)),
  };
}
