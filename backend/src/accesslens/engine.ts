/**
 * AccessLens rules engine. Everything here is computed from data Okta itself provides
 * (users and their profile, app assignments, admin roles, SSO sign-in events) plus our own
 * policy config (app sensitivity, thresholds, toxic pairs). Okta has no notion of roles,
 * cohorts or findings, so none of that is read from a file.
 *
 *  1. Cohorts (the "role" we infer). Users whose Okta profile has a department are grouped by
 *     department (and team, when it differs). Users with no department are placed in the
 *     cohort whose app set they most resemble (IDF-weighted cosine similarity), so a missing
 *     HR attribute doesn't hide someone from the review.
 *  2. Findings. Eight rules, scored as rule weight x app sensitivity (x a usage-age factor for
 *     unused / never-used access), matching the AccessLens PRD.
 */

export type Sensitivity = "low" | "medium" | "high" | "critical";

export interface EngineUser {
  id: number;
  firstName: string;
  name: string;
  status: string;
  department: string | null;
  team: string | null;
}
export interface EngineApp {
  id: number;
  key: string;
  sensitivity: Sensitivity;
}
export interface EngineAssignment {
  userId: number;
  appId: number;
  source: "GROUP" | "DIRECT";
  assignedAt: string | null;
}
export interface EngineUsage {
  userId: number;
  appId: number;
  lastSsoAt: string | null;
}
export interface EngineAdminRole {
  userId: number;
  role: string;
}
export interface EngineConfig {
  thresholds: {
    unused_days: number;
    never_used_days: number;
    outlier_share: number;
    missing_share: number;
    min_cohort_size: number;
  };
  rule_weights: Record<string, number>;
  sensitivity_scale: Record<Sensitivity, number>;
  toxic_pairs: { app_a: string; app_b: string; reason: string }[];
  /** Departments allowed to hold Okta admin roles. Default: IT, Security. */
  admin_departments?: string[];
  /** Below this similarity a user with no department is left without a cohort. Default 0.5. */
  min_inferred_similarity?: number;
}

export interface EngineCohort {
  _id: number;
  key: string;
  label: string;
  department: string | null;
  /** Mean similarity of the cohort's active members to its app profile (0..1). */
  confidence: number;
  /** Active members. */
  size: number;
}
export interface EngineMembership {
  user_id: number;
  cohort_id: number;
  similarity: number;
  /** True when the cohort came from the user's apps because Okta has no department. */
  inferred: boolean;
}
export interface EngineFinding {
  _id: number;
  user_id: number;
  app_id: number | null;
  rule: string;
  risk_score: number;
  evidence: Record<string, unknown>;
  explanation: string;
  status: "open";
}

const DAY = 86_400_000;
const round = (n: number, places: number) => Math.round(n * 10 ** places) / 10 ** places;

function cohortKey(department: string, team: string | null): string {
  return team && team !== department ? `${department} / ${team}` : department;
}

/** IDF-weighted cosine similarity between a user's apps and a cohort's app shares. */
function similarity(held: Set<number>, shares: Map<number, number>, idf: Map<number, number>): number {
  let dot = 0;
  let nu = 0;
  let nc = 0;
  for (const a of held) {
    const w = idf.get(a) ?? 0;
    nu += w * w;
    dot += w * (shares.get(a) ?? 0) * w;
  }
  for (const [a, s] of shares) nc += (s * (idf.get(a) ?? 0)) ** 2;
  return nu && nc ? dot / Math.sqrt(nu * nc) : 0;
}

export function inferCohorts(
  users: EngineUser[],
  appsOf: Map<number, Set<number>>,
  minSimilarity = 0.5
): { cohorts: EngineCohort[]; membership: Map<number, EngineMembership> } {
  const active = users.filter((u) => u.status === "ACTIVE");
  const held = (id: number) => appsOf.get(id) ?? new Set<number>();

  // Apps nearly everyone has (chat, email) say little about a role; weight rare apps up.
  const df = new Map<number, number>();
  for (const u of active) for (const a of held(u.id)) df.set(a, (df.get(a) ?? 0) + 1);
  const idf = new Map([...df].map(([a, n]) => [a, Math.log(active.length / n)]));

  // Cohorts from the Okta profile; their app profile comes from active members only.
  const keys = [...new Set(users.filter((u) => u.department).map((u) => cohortKey(u.department!, u.team)))].sort();
  const cohortIdOf = new Map(keys.map((k, i) => [k, i + 1]));
  const sharesOf = (members: EngineUser[]) => {
    const counts = new Map<number, number>();
    for (const u of members) for (const a of held(u.id)) counts.set(a, (counts.get(a) ?? 0) + 1);
    return new Map([...counts].map(([a, n]) => [a, n / members.length]));
  };
  const profile = new Map<number, Map<number, number>>();
  for (const k of keys) {
    const members = active.filter((u) => u.department && cohortKey(u.department, u.team) === k);
    if (members.length) profile.set(cohortIdOf.get(k)!, sharesOf(members));
  }

  const membership = new Map<number, EngineMembership>();
  for (const u of users) {
    const apps = held(u.id);
    if (u.department) {
      const id = cohortIdOf.get(cohortKey(u.department, u.team))!;
      const shares = profile.get(id);
      membership.set(u.id, {
        user_id: u.id,
        cohort_id: id,
        similarity: round(shares ? similarity(apps, shares, idf) : 0, 2),
        inferred: false,
      });
      continue;
    }
    let best: { id: number; sim: number } | null = null;
    for (const [id, shares] of profile) {
      const sim = similarity(apps, shares, idf);
      if (!best || sim > best.sim) best = { id, sim };
    }
    if (best && best.sim >= minSimilarity) {
      membership.set(u.id, { user_id: u.id, cohort_id: best.id, similarity: round(best.sim, 2), inferred: true });
    }
  }

  const cohorts: EngineCohort[] = keys.map((k) => {
    const id = cohortIdOf.get(k)!;
    const members = active.filter((u) => membership.get(u.id)?.cohort_id === id);
    const sims = members.map((u) => membership.get(u.id)!.similarity);
    return {
      _id: id,
      key: k.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
      label: k,
      department: users.find((u) => u.department && cohortKey(u.department, u.team) === k)?.department ?? null,
      confidence: sims.length ? round(sims.reduce((s, x) => s + x, 0) / sims.length, 2) : 0,
      size: members.length,
    };
  });
  return { cohorts, membership };
}

export function computeFindings(input: {
  now: Date;
  users: EngineUser[];
  apps: EngineApp[];
  assignments: EngineAssignment[];
  usage: EngineUsage[];
  adminRoles: EngineAdminRole[];
  config: EngineConfig;
  cohorts: EngineCohort[];
  membership: Map<number, EngineMembership>;
}): EngineFinding[] {
  const { now, users, apps, assignments, usage, adminRoles, config, cohorts, membership } = input;
  const t = config.thresholds;
  const weight = (rule: string) => config.rule_weights[rule] ?? 1;
  const sens = (s: Sensitivity) => config.sensitivity_scale[s] ?? 1;
  const ageFactor = (days: number) => Math.min(1 + days / 30, 7);
  const days = (iso: string | null) => (iso ? Math.max(0, Math.floor((now.getTime() - new Date(iso).getTime()) / DAY)) : null);
  const pct = (share: number) => `${Math.round(share * 100)}%`;
  const adminDepts = new Set((config.admin_departments ?? ["IT", "Security"]).map((d) => d.toLowerCase()));

  const appById = new Map(apps.map((a) => [a.id, a]));
  const appByKey = new Map(apps.map((a) => [a.key, a]));
  const cohortById = new Map(cohorts.map((c) => [c._id, c]));
  const lastSso = new Map(usage.map((u) => [`${u.userId}:${u.appId}`, u.lastSsoAt]));
  const assignedTo = new Map<number, EngineAssignment[]>();
  for (const a of assignments) assignedTo.set(a.userId, [...(assignedTo.get(a.userId) ?? []), a]);

  // Share of each cohort's active members holding each app (the member themself included).
  const cohortShares = new Map<number, Map<number, number>>();
  for (const c of cohorts) {
    const members = users.filter((u) => u.status === "ACTIVE" && membership.get(u.id)?.cohort_id === c._id);
    const counts = new Map<number, number>();
    for (const u of members) for (const a of assignedTo.get(u.id) ?? []) counts.set(a.appId, (counts.get(a.appId) ?? 0) + 1);
    cohortShares.set(c._id, new Map([...counts].map(([a, n]) => [a, n / members.length])));
  }

  const out: EngineFinding[] = [];
  const add = (f: Omit<EngineFinding, "_id" | "status">) =>
    out.push({ ...f, risk_score: round(f.risk_score, 1), _id: out.length + 1, status: "open" });

  for (const u of users) {
    const held = (assignedTo.get(u.id) ?? []).filter((a) => appById.has(a.appId));

    if (u.status !== "ACTIVE") {
      for (const a of held) {
        const app = appById.get(a.appId)!;
        add({
          user_id: u.id,
          app_id: app.id,
          rule: "STALE_ACCOUNT",
          risk_score: weight("STALE_ACCOUNT") * sens(app.sensitivity),
          evidence: { okta_status: u.status },
          explanation: `${u.name} is ${u.status.toLowerCase()} in Okta but still assigned to ${app.key}.`,
        });
      }
      continue;
    }

    const m = membership.get(u.id);
    const cohort = m ? cohortById.get(m.cohort_id) : undefined;
    const shares = cohort && cohort.size >= t.min_cohort_size ? cohortShares.get(cohort._id) : undefined;

    for (const a of held) {
      const app = appById.get(a.appId)!;
      const last = lastSso.get(`${u.id}:${app.id}`) ?? null;
      const since = days(last);
      const assignedDays = days(a.assignedAt);
      if (since == null && assignedDays != null && assignedDays >= t.never_used_days) {
        add({
          user_id: u.id,
          app_id: app.id,
          rule: "NEVER_USED",
          risk_score: weight("NEVER_USED") * sens(app.sensitivity) * ageFactor(assignedDays),
          evidence: { assigned_days: assignedDays },
          explanation: `Assigned ${assignedDays} days ago to ${app.key}; no Okta sign-in ever seen.`,
        });
      } else if (since != null && since >= t.unused_days) {
        add({
          user_id: u.id,
          app_id: app.id,
          rule: "UNUSED_ACCESS",
          risk_score: weight("UNUSED_ACCESS") * sens(app.sensitivity) * ageFactor(since),
          evidence: { last_sso: last, days_inactive: since },
          explanation: `No sign-in to ${app.key} for ${since} days.`,
        });
      }
      if (a.source === "DIRECT") {
        add({
          user_id: u.id,
          app_id: app.id,
          rule: "DIRECT_ASSIGNMENT",
          risk_score: weight("DIRECT_ASSIGNMENT") * sens(app.sensitivity),
          evidence: { source: "DIRECT" },
          explanation: `${app.key} assigned directly, bypassing group policy.`,
        });
      }
      const share = shares?.get(app.id);
      if (cohort && share != null && share < t.outlier_share) {
        add({
          user_id: u.id,
          app_id: app.id,
          rule: "OUTLIER_ACCESS",
          risk_score: weight("OUTLIER_ACCESS") * sens(app.sensitivity),
          evidence: { cohort: cohort.label, cohort_share: round(share, 3), low_confidence: m!.inferred && m!.similarity < 0.8 },
          explanation: `Only ${pct(share)} of ${cohort.label} hold ${app.key}.`,
        });
      }
    }

    if (shares) {
      const heldIds = new Set(held.map((a) => a.appId));
      for (const [appId, share] of shares) {
        const app = appById.get(appId);
        if (!app || heldIds.has(appId) || share < t.missing_share) continue;
        add({
          user_id: u.id,
          app_id: appId,
          rule: "MISSING_ACCESS",
          risk_score: weight("MISSING_ACCESS") * sens(app.sensitivity),
          evidence: { cohort_share: round(share, 3) },
          explanation: `${pct(share)} of the cohort has ${app.key}; ${u.firstName} does not.`,
        });
      }
    }

    const dept = (cohort?.department ?? u.department ?? "").toLowerCase();
    if (!adminDepts.has(dept)) {
      const oktaAdmin = appByKey.get("okta-admin");
      for (const r of adminRoles.filter((r) => r.userId === u.id)) {
        add({
          user_id: u.id,
          app_id: oktaAdmin?.id ?? null,
          rule: "PRIVILEGED_ROLE",
          risk_score: weight("PRIVILEGED_ROLE") * (oktaAdmin ? sens(oktaAdmin.sensitivity) : sens("critical")),
          evidence: { role: r.role, cohort: cohort?.label ?? null },
          explanation: `${u.name} holds Okta ${r.role} outside IT/Security.`,
        });
      }
    }

    const heldKeys = new Set(held.map((a) => appById.get(a.appId)!.key));
    for (const p of config.toxic_pairs) {
      if (!heldKeys.has(p.app_a) || !heldKeys.has(p.app_b)) continue;
      const a = appByKey.get(p.app_a)!;
      const b = appByKey.get(p.app_b)!;
      add({
        user_id: u.id,
        app_id: null,
        rule: "TOXIC_COMBINATION",
        risk_score: weight("TOXIC_COMBINATION") * Math.min(sens(a.sensitivity), sens(b.sensitivity)),
        evidence: { apps: [p.app_a, p.app_b] },
        explanation: p.reason,
      });
    }
  }
  return out;
}
