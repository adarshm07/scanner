import fs from "fs";
import path from "path";
import { EngineConfig, computeFindings, inferCohorts } from "./engine";

/**
 * AccessLens dummy dataset (synthetic Okta workforce tenant). The JSON files under
 * backend/data/accesslens are the MongoDB export from the PRD's seed script; this module
 * loads them once and joins them into per-user access views. No database needed for the demo.
 *
 * Only data Okta can give us is read here (users, apps, assignments, groups, admin roles,
 * SSO usage) plus our policy config. Cohorts and findings are computed by ./engine; the
 * seed's cohorts.json, user_cohorts.json and findings.json are not read (expected_findings.json
 * is the answer key the tests check the engine against).
 *
 * Override the folder with ACCESSLENS_DATA_DIR.
 */

type MongoDate = { $date: string } | string | null | undefined;

interface RawUser {
  _id: number;
  okta_id: string;
  email: string;
  first_name: string;
  last_name: string;
  status: string;
  created: MongoDate;
  last_login: MongoDate;
  title: string | null;
  department: string | null;
  team: string | null;
  manager_id: number | null;
  employee_type: string;
  country_code: string;
  github_username?: string | null;
  github_owner?: string | null;
  github_repo?: string | null;
  github_repo_url?: string | null;
  github_pat?: string | null;
}
interface RawApp {
  _id: number;
  okta_id: string;
  key: string;
  label: string;
  sensitivity: Sensitivity;
  sign_on_mode: string;
  status: string;
}
interface RawAssignment {
  _id: number;
  user_id: number;
  app_id: number;
  source: "GROUP" | "DIRECT";
  via_group_id: number | null;
  assigned_at: MongoDate;
  status: string;
  sync_state: string;
}
interface RawUsage {
  user_id: number;
  app_id: number;
  last_sso_at: MongoDate;
  sso_count_90d: number;
}
interface RawGroup {
  _id: number;
  okta_id: string;
  name: string;
  description: string;
}
interface RawFinding {
  _id: number;
  user_id: number;
  app_id: number | null;
  rule: string;
  risk_score: number;
  evidence: Record<string, unknown>;
  explanation: string;
  status: string;
}
interface RawOktaAssignment {
  app_id: string;
  id: string;
  profile?: { roles?: string[] };
}
type RawConfig = EngineConfig;

export type Sensitivity = "low" | "medium" | "high" | "critical";

export interface Finding {
  id: number;
  rule: string;
  riskScore: number;
  explanation: string;
  appKey: string | null;
  evidence: Record<string, unknown>;
}

export interface AppAccess {
  appId: number;
  appKey: string;
  appLabel: string;
  sensitivity: Sensitivity;
  signOnMode: string;
  /** App-level roles from the Okta assignment profile (e.g. "user", "admin"). */
  appRoles: string[];
  /** How the access was granted. */
  source: "GROUP" | "DIRECT";
  viaGroup: string | null;
  status: string;
  syncState: string;
  assignedAt: string | null;
  assignedDays: number | null;
  lastSsoAt: string | null;
  daysSinceUse: number | null;
  ssoCount90d: number;
  /** Share of the user's cohort that also holds this app (0..1). */
  cohortShare: number | null;
  findings: Finding[];
}

export interface MissingApp {
  appKey: string;
  appLabel: string;
  sensitivity: Sensitivity;
  cohortShare: number;
}

export interface GitHubAccessConfig {
  username: string | null;
  owner: string | null;
  repo: string | null;
  repoUrl: string | null;
  tokenConfigured: boolean;
}

export interface UserSummary {
  id: number;
  oktaId: string;
  name: string;
  email: string;
  status: string;
  title: string | null;
  department: string | null;
  team: string | null;
  employeeType: string;
  country: string;
  manager: { id: number; name: string } | null;
  created: string | null;
  lastLogin: string | null;
  cohort: { key: string; label: string; confidence: number; similarity: number; isOverride: boolean; inferred: boolean } | null;
  adminRoles: string[];
  groups: string[];
  appCount: number;
  findingCount: number;
  riskScore: number;
  topRules: string[];
  github: GitHubAccessConfig | null;
}

export interface UserDetail extends UserSummary {
  access: AppAccess[];
  missing: MissingApp[];
  userFindings: Finding[]; // findings not tied to one app (e.g. toxic combinations)
  cohortSize: number;
}

export interface Dataset {
  tenant: { domain: string; lastSyncAt: string | null };
  now: Date;
  thresholds: RawConfig["thresholds"];
  toxicPairs: RawConfig["toxic_pairs"];
  apps: RawApp[];
  users: UserSummary[];
  detail: Map<number, UserDetail>;
}

const DAY = 86_400_000;

function toIso(d: MongoDate): string | null {
  if (!d) return null;
  return typeof d === "string" ? d : d.$date;
}

function daysBetween(from: string | null, now: Date): number | null {
  if (!from) return null;
  return Math.max(0, Math.floor((now.getTime() - new Date(from).getTime()) / DAY));
}

export function dataDir(): string {
  return process.env.ACCESSLENS_DATA_DIR?.trim() || path.resolve(__dirname, "../../data/accesslens");
}

function read<T>(dir: string, name: string): T {
  return JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), "utf8")) as T;
}

function readOptional<T>(dir: string, name: string): T | null {
  const file = path.join(dir, `${name}.json`);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

export function buildDataset(dir = dataDir()): Dataset {
  const baseUsers = read<RawUser[]>(dir, "users");
  const demoUsersFile = readOptional<{ users?: RawUser[]; assignments?: RawAssignment[]; usage?: RawUsage[]; admin_roles?: { user_id: number; role_type: string }[] }>(dir, "demo_users");
  const users = [...baseUsers, ...(demoUsersFile?.users ?? [])];
  const apps = read<RawApp[]>(dir, "apps");
  const assignments = [...read<RawAssignment[]>(dir, "assignments"), ...(demoUsersFile?.assignments ?? [])];
  const usage = [...read<RawUsage[]>(dir, "app_usage"), ...(demoUsersFile?.usage ?? [])];
  const groups = read<RawGroup[]>(dir, "groups");
  const groupMembers = read<{ group_id: number; user_id: number }[]>(dir, "group_members");
  const adminRoles = [...read<{ user_id: number; role_type: string }[]>(dir, "admin_roles"), ...(demoUsersFile?.admin_roles ?? [])];
  const oktaAssignments = read<RawOktaAssignment[]>(dir, "okta_app_assignments");
  const config = read<RawConfig[]>(dir, "config")[0];
  const tenant = read<{ okta_domain: string; last_sync_at: MongoDate }[]>(dir, "tenants")[0];

  // Day counts are relative to the last sync, so the demo reads the same on any date.
  const lastSync = toIso(tenant?.last_sync_at);
  const now = lastSync ? new Date(lastSync) : new Date();

  // Infer each user's cohort (role) and run the rules over the raw Okta data.
  const heldApps = new Map<number, Set<number>>();
  for (const a of assignments) heldApps.set(a.user_id, (heldApps.get(a.user_id) ?? new Set()).add(a.app_id));
  const engineUsers = users.map((u) => ({
    id: u._id,
    firstName: u.first_name,
    name: `${u.first_name} ${u.last_name}`,
    status: u.status,
    department: u.department,
    team: u.team,
  }));
  const { cohorts, membership } = inferCohorts(engineUsers, heldApps, config.min_inferred_similarity);
  const userCohorts = [...membership.values()];
  const findings: RawFinding[] = computeFindings({
    now,
    users: engineUsers,
    apps: apps.map((a) => ({ id: a._id, key: a.key, sensitivity: a.sensitivity })),
    assignments: assignments.map((a) => ({ userId: a.user_id, appId: a.app_id, source: a.source, assignedAt: toIso(a.assigned_at) })),
    usage: usage.map((u) => ({ userId: u.user_id, appId: u.app_id, lastSsoAt: toIso(u.last_sso_at) })),
    adminRoles: adminRoles.map((r) => ({ userId: r.user_id, role: r.role_type })),
    config,
    cohorts,
    membership,
  });

  const appById = new Map(apps.map((a) => [a._id, a]));
  const appByOkta = new Map(apps.map((a) => [a.okta_id, a]));
  const userById = new Map(users.map((u) => [u._id, u]));
  const userByOkta = new Map(users.map((u) => [u.okta_id, u]));
  const groupById = new Map(groups.map((g) => [g._id, g]));
  const cohortById = new Map(cohorts.map((c) => [c._id, c]));
  const cohortOf = new Map(userCohorts.map((uc) => [uc.user_id, uc]));
  const usageKey = (u: number, a: number) => `${u}:${a}`;
  const usageMap = new Map(usage.map((u) => [usageKey(u.user_id, u.app_id), u]));

  const appRoles = new Map<string, string[]>();
  for (const oa of oktaAssignments) {
    const u = userByOkta.get(oa.id);
    const a = appByOkta.get(oa.app_id);
    if (u && a) appRoles.set(usageKey(u._id, a._id), oa.profile?.roles ?? []);
  }

  const groupsOf = new Map<number, string[]>();
  for (const gm of groupMembers) {
    const g = groupById.get(gm.group_id);
    if (!g) continue;
    const list = groupsOf.get(gm.user_id) ?? [];
    list.push(g.name);
    groupsOf.set(gm.user_id, list);
  }

  const adminOf = new Map<number, string[]>();
  for (const r of adminRoles) adminOf.set(r.user_id, [...(adminOf.get(r.user_id) ?? []), r.role_type]);

  const appsOf = new Map<number, RawAssignment[]>();
  for (const a of assignments) appsOf.set(a.user_id, [...(appsOf.get(a.user_id) ?? []), a]);

  // Cohort membership and per-cohort app share (active users only, like the PRD's rules).
  const cohortMembers = new Map<number, number[]>();
  for (const uc of userCohorts) {
    if (userById.get(uc.user_id)?.status !== "ACTIVE") continue;
    cohortMembers.set(uc.cohort_id, [...(cohortMembers.get(uc.cohort_id) ?? []), uc.user_id]);
  }
  const cohortShare = new Map<number, Map<number, number>>();
  for (const [cid, members] of cohortMembers) {
    const counts = new Map<number, number>();
    for (const uid of members) {
      for (const a of appsOf.get(uid) ?? []) counts.set(a.app_id, (counts.get(a.app_id) ?? 0) + 1);
    }
    const shares = new Map<number, number>();
    for (const [aid, n] of counts) shares.set(aid, n / members.length);
    cohortShare.set(cid, shares);
  }

  const findingsOf = new Map<number, RawFinding[]>();
  for (const f of findings) {
    if (f.status !== "open") continue;
    findingsOf.set(f.user_id, [...(findingsOf.get(f.user_id) ?? []), f]);
  }
  const toFinding = (f: RawFinding): Finding => ({
    id: f._id,
    rule: f.rule,
    riskScore: f.risk_score,
    explanation: f.explanation,
    appKey: f.app_id != null ? appById.get(f.app_id)?.key ?? null : null,
    evidence: f.evidence ?? {},
  });

  const sensRank: Record<Sensitivity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const detail = new Map<number, UserDetail>();
  const summaries: UserSummary[] = [];

  for (const u of users) {
    const uc = cohortOf.get(u._id);
    const cohort = uc ? cohortById.get(uc.cohort_id) : undefined;
    const shares = uc ? cohortShare.get(uc.cohort_id) : undefined;
    const uFindings = findingsOf.get(u._id) ?? [];
    const held = new Set<number>();

    const access: AppAccess[] = (appsOf.get(u._id) ?? [])
      .map((a): AppAccess | null => {
        const app = appById.get(a.app_id);
        if (!app) return null;
        held.add(app._id);
        const use = usageMap.get(usageKey(u._id, app._id));
        const assignedAt = toIso(a.assigned_at);
        const lastSso = toIso(use?.last_sso_at);
        return {
          appId: app._id,
          appKey: app.key,
          appLabel: app.label,
          sensitivity: app.sensitivity,
          signOnMode: app.sign_on_mode,
          appRoles: appRoles.get(usageKey(u._id, app._id)) ?? [],
          source: a.source,
          viaGroup: a.via_group_id != null ? groupById.get(a.via_group_id)?.name ?? null : null,
          status: a.status,
          syncState: a.sync_state,
          assignedAt,
          assignedDays: daysBetween(assignedAt, now),
          lastSsoAt: lastSso,
          daysSinceUse: daysBetween(lastSso, now),
          ssoCount90d: use?.sso_count_90d ?? 0,
          cohortShare: shares ? Math.round((shares.get(app._id) ?? 0) * 1000) / 1000 : null,
          findings: uFindings
            .filter((f) => f.app_id === app._id && f.rule !== "MISSING_ACCESS")
            .map(toFinding),
        };
      })
      .filter((x): x is AppAccess => x !== null)
      .sort((a, b) => sensRank[a.sensitivity] - sensRank[b.sensitivity] || a.appLabel.localeCompare(b.appLabel));

    // Apps most of the cohort has that this user lacks.
    const missing: MissingApp[] = [];
    if (shares && (cohortMembers.get(uc!.cohort_id)?.length ?? 0) >= config.thresholds.min_cohort_size) {
      for (const [aid, share] of shares) {
        if (held.has(aid) || share < config.thresholds.missing_share) continue;
        const app = appById.get(aid);
        if (app) missing.push({ appKey: app.key, appLabel: app.label, sensitivity: app.sensitivity, cohortShare: Math.round(share * 1000) / 1000 });
      }
    }
    for (const f of uFindings) {
      if (f.rule !== "MISSING_ACCESS" || f.app_id == null) continue;
      const app = appById.get(f.app_id);
      if (app && !missing.some((m) => m.appKey === app.key)) {
        missing.push({ appKey: app.key, appLabel: app.label, sensitivity: app.sensitivity, cohortShare: Number(f.evidence?.cohort_share ?? 0) });
      }
    }
    missing.sort((a, b) => b.cohortShare - a.cohortShare);

    const mgr = u.manager_id != null ? userById.get(u.manager_id) : undefined;
    const github = (u.github_pat || u.github_repo_url || u.github_owner || u.github_repo || u.github_username)
      ? {
          username: u.github_username ?? null,
          owner: u.github_owner ?? null,
          repo: u.github_repo ?? null,
          repoUrl: u.github_repo_url ?? (u.github_owner && u.github_repo ? `https://github.com/${u.github_owner}/${u.github_repo}` : null),
          tokenConfigured: !!(u.github_pat ?? "").trim(),
        }
      : null;
    const summary: UserSummary = {
      id: u._id,
      oktaId: u.okta_id,
      name: `${u.first_name} ${u.last_name}`,
      email: u.email,
      status: u.status,
      title: u.title,
      department: u.department,
      team: u.team,
      employeeType: u.employee_type,
      country: u.country_code,
      manager: mgr ? { id: mgr._id, name: `${mgr.first_name} ${mgr.last_name}` } : null,
      created: toIso(u.created),
      lastLogin: toIso(u.last_login),
      cohort:
        cohort && uc
          ? { key: cohort.key, label: cohort.label, confidence: cohort.confidence, similarity: uc.similarity, isOverride: false, inferred: uc.inferred }
          : null,
      adminRoles: adminOf.get(u._id) ?? [],
      groups: groupsOf.get(u._id) ?? [],
      appCount: access.length,
      findingCount: uFindings.length,
      riskScore: Math.round(uFindings.reduce((s, f) => s + f.risk_score, 0) * 10) / 10,
      topRules: [...new Set(uFindings.sort((a, b) => b.risk_score - a.risk_score).map((f) => f.rule))],
      github,
    };
    summaries.push(summary);
    detail.set(u._id, {
      ...summary,
      access,
      missing,
      // Findings not attached to a held app (toxic pairs, Okta admin roles without an assignment).
      userFindings: uFindings
        .filter((f) => f.rule !== "MISSING_ACCESS" && (f.app_id == null || !held.has(f.app_id)))
        .map(toFinding),
      cohortSize: uc ? cohortMembers.get(uc.cohort_id)?.length ?? 0 : 0,
    });
  }

  return {
    tenant: { domain: tenant?.okta_domain ?? "unknown", lastSyncAt: lastSync },
    now,
    thresholds: config.thresholds,
    toxicPairs: config.toxic_pairs ?? [],
    apps,
    users: summaries,
    detail,
  };
}

export function loadUserGitHubCredentials(userId: number): {
  token: string;
  owner: string;
  repo: string;
  repoUrl: string;
  username: string;
} | null {
  const demoUsers = readOptional<{ users?: RawUser[] }>(dataDir(), "demo_users");
  const user = demoUsers?.users?.find((u) => u._id === userId);
  if (!user) return null;
  const token = (user.github_pat ?? "").trim();
  const owner = (user.github_owner ?? "").trim();
  const repo = (user.github_repo ?? "").trim();
  const repoUrl = (user.github_repo_url ?? "").trim() || (owner && repo ? `https://github.com/${owner}/${repo}` : "");
  if (!token || !owner || !repo || !repoUrl) return null;
  return {
    token,
    owner,
    repo,
    repoUrl,
    username: (user.github_username ?? user.email ?? "").trim(),
  };
}

let cached: Dataset | null = null;
export function getDataset(): Dataset {
  if (!cached) cached = buildDataset();
  return cached;
}
