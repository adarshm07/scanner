import { LlmProvider, callLlmJson } from "../llm";
import { Dataset, UserDetail } from "./data";

/**
 * Access review: does this user need each app they hold, given their role?
 *
 * Two layers, per the AccessLens PRD:
 *  - a deterministic baseline from the rule findings (always computed), and
 *  - an LLM judgement that reads the user's role (title / department / team / inferred
 *    cohort), the access type and usage of every app, and how common each app is in the
 *    cohort, then says keep / review / revoke with a reason.
 * The model only recommends; nothing is changed in Okta. Prompts are pseudonymous: no
 * names, emails or Okta IDs leave the server.
 */

export type Verdict = "keep" | "review" | "revoke";
export type Confidence = "high" | "medium" | "low";

export interface AppDecision {
  appKey: string;
  verdict: Verdict;
  reason: string;
  confidence: Confidence;
  /** The rules-only verdict, for comparison. */
  ruleVerdict: Verdict;
}

export interface MissingDecision {
  appKey: string;
  verdict: "grant" | "skip";
  reason: string;
}

export interface UserReview {
  userId: number;
  engine: "llm" | "rules";
  provider: string | null;
  roleAssessment: string;
  summary: string;
  decisions: AppDecision[];
  missing: MissingDecision[];
  generatedAt: string;
  error?: string;
}

const REVOKE_RULES = new Set(["STALE_ACCOUNT", "NEVER_USED", "UNUSED_ACCESS"]);
const REVIEW_RULES = new Set(["OUTLIER_ACCESS", "PRIVILEGED_ROLE", "TOXIC_COMBINATION", "DIRECT_ASSIGNMENT"]);

function roleLine(u: UserDetail): string {
  const parts = [u.title, u.department, u.team].filter(Boolean);
  return parts.length ? parts.join(" / ") : "no title or department in Okta";
}

/** Rules-only verdict for one app. */
export function ruleVerdict(u: UserDetail, appKey: string, ds: Dataset): { verdict: Verdict; reason: string } {
  if (u.status !== "ACTIVE") {
    return { verdict: "revoke", reason: `Account is ${u.status.toLowerCase()} in Okta but the app is still assigned.` };
  }
  const a = u.access.find((x) => x.appKey === appKey);
  if (!a) return { verdict: "review", reason: "Unknown app." };
  const priv = u.userFindings.find((f) => f.rule === "PRIVILEGED_ROLE" && f.appKey === appKey);
  if (priv) return { verdict: "review", reason: priv.explanation };
  const revoke = a.findings.find((f) => REVOKE_RULES.has(f.rule));
  if (revoke) return { verdict: "revoke", reason: revoke.explanation };
  const toxic = u.userFindings.find((f) => f.rule === "TOXIC_COMBINATION" && (f.evidence.apps as string[] | undefined)?.includes(appKey));
  if (toxic) return { verdict: "review", reason: `Separation-of-duties conflict: ${toxic.explanation}.` };
  const review = a.findings.find((f) => REVIEW_RULES.has(f.rule));
  if (review) return { verdict: "review", reason: review.explanation };
  if (a.daysSinceUse == null && (a.assignedDays ?? 0) >= ds.thresholds.never_used_days) {
    return { verdict: "revoke", reason: `Assigned ${a.assignedDays} days ago and never signed in.` };
  }
  if (a.daysSinceUse != null && a.daysSinceUse >= ds.thresholds.unused_days) {
    return { verdict: "revoke", reason: `No sign-in for ${a.daysSinceUse} days.` };
  }
  return { verdict: "keep", reason: "Used recently and common for this cohort." };
}

export function rulesReview(u: UserDetail, ds: Dataset, error?: string): UserReview {
  const decisions = u.access.map((a) => {
    const r = ruleVerdict(u, a.appKey, ds);
    return { appKey: a.appKey, verdict: r.verdict, reason: r.reason, confidence: "medium" as Confidence, ruleVerdict: r.verdict };
  });
  const counts = tally(decisions.map((d) => d.verdict));
  return {
    userId: u.id,
    engine: "rules",
    provider: null,
    roleAssessment: u.cohort
      ? `Grouped with ${u.cohort.label} (${Math.round(u.cohort.similarity * 100)}% access similarity). Okta role: ${roleLine(u)}.`
      : `No cohort. Okta role: ${roleLine(u)}.`,
    summary: [
      `${counts.keep} keep, ${counts.review} to review, ${counts.revoke} to revoke (rules only).`,
      ...u.userFindings.map((f) => `Review: ${f.explanation}`),
    ].join(" "),
    decisions,
    missing:
      u.status === "ACTIVE"
        ? u.missing.map((m) => ({ appKey: m.appKey, verdict: "grant" as const, reason: `${Math.round(m.cohortShare * 100)}% of the cohort has it.` }))
        : [],
    generatedAt: new Date().toISOString(),
    ...(error ? { error } : {}),
  };
}

function tally(vs: Verdict[]): Record<Verdict, number> {
  return vs.reduce((acc, v) => ((acc[v] += 1), acc), { keep: 0, review: 0, revoke: 0 } as Record<Verdict, number>);
}

/** Pseudonymous payload for the model: role context + access, no identities. */
export function buildReviewPayload(u: UserDetail, ds: Dataset) {
  return {
    user: {
      status: u.status,
      title: u.title,
      department: u.department,
      team: u.team,
      employee_type: u.employeeType,
      tenure_days: u.created ? Math.floor((ds.now.getTime() - new Date(u.created).getTime()) / 86_400_000) : null,
      days_since_okta_login: u.lastLogin ? Math.floor((ds.now.getTime() - new Date(u.lastLogin).getTime()) / 86_400_000) : null,
      has_manager: u.manager != null,
      inferred_cohort: u.cohort ? { label: u.cohort.label, cohort_confidence: u.cohort.confidence, similarity: u.cohort.similarity } : null,
      cohort_size: u.cohortSize,
      okta_admin_roles: u.adminRoles,
      groups: u.groups,
    },
    access: u.access.map((a) => ({
      app: a.appKey,
      name: a.appLabel,
      sensitivity: a.sensitivity,
      app_roles: a.appRoles,
      granted_via: a.source === "DIRECT" ? "direct assignment" : `group ${a.viaGroup}`,
      assigned_days_ago: a.assignedDays,
      days_since_last_sso: a.daysSinceUse,
      sso_count_90d: a.ssoCount90d,
      cohort_share: a.cohortShare,
      rule_flags: a.findings.map((f) => f.rule),
    })),
    user_level_flags: u.userFindings.map((f) => ({ rule: f.rule, detail: f.explanation })),
    apps_common_in_cohort_but_missing: u.missing.map((m) => ({ app: m.appKey, name: m.appLabel, sensitivity: m.sensitivity, cohort_share: m.cohortShare })),
    policy: {
      unused_days: ds.thresholds.unused_days,
      never_used_days: ds.thresholds.never_used_days,
      toxic_pairs: ds.toxicPairs,
    },
  };
}

const SYSTEM = `You are an identity-governance reviewer for an Okta workforce tenant.
For ONE user, decide whether they need each app they currently hold, based on their role.
The role comes from their Okta title/department/team when present, otherwise from the inferred peer cohort.
Weigh: does the app fit the role; is it used (days_since_last_sso, sso_count_90d); how common it is in the cohort (cohort_share); app sensitivity; how it was granted; app_roles; rule_flags; and account status.
Guidance: deprovisioned or suspended users should lose all access. Never-used or long-unused access to high/critical apps should usually be revoked. Rare access for the cohort to sensitive apps needs review unless the title clearly justifies it. Okta admin roles outside IT/Security need review. Low-sensitivity baseline apps (chat, email, video) are normally kept for active users.
Also judge each app in apps_common_in_cohort_but_missing: should the user be granted it ("grant") or not ("skip")?
Reply with JSON only, no prose, in this shape:
{"role_assessment":"one sentence on the role this user most likely holds and why",
 "summary":"one or two sentences for the reviewer",
 "decisions":[{"app":"<app key>","verdict":"keep|review|revoke","confidence":"high|medium|low","reason":"<= 25 words"}],
 "missing":[{"app":"<app key>","verdict":"grant|skip","reason":"<= 20 words"}]}
Include every app from "access" exactly once in decisions. Use the app keys as given.`;

interface LlmReply {
  role_assessment?: string;
  summary?: string;
  decisions?: { app?: string; verdict?: string; confidence?: string; reason?: string }[];
  missing?: { app?: string; verdict?: string; reason?: string }[];
}

const VERDICTS = new Set<Verdict>(["keep", "review", "revoke"]);
const CONFIDENCES = new Set<Confidence>(["high", "medium", "low"]);

/** Merge the model's reply with the rules baseline; anything it skipped falls back to rules. */
export function mergeReply(u: UserDetail, ds: Dataset, reply: LlmReply, provider: string): UserReview {
  const base = rulesReview(u, ds);
  const byApp = new Map((Array.isArray(reply.decisions) ? reply.decisions : []).filter((d) => d?.app).map((d) => [String(d.app), d]));
  const decisions = base.decisions.map((b) => {
    const d = byApp.get(b.appKey);
    const verdict = d && VERDICTS.has(d.verdict as Verdict) ? (d.verdict as Verdict) : null;
    if (!d || !verdict) return { ...b, reason: `${b.reason} (model gave no verdict; rules used)` };
    return {
      appKey: b.appKey,
      verdict,
      confidence: CONFIDENCES.has(d.confidence as Confidence) ? (d.confidence as Confidence) : "medium",
      reason: String(d.reason ?? "").slice(0, 300) || b.reason,
      ruleVerdict: b.ruleVerdict,
    };
  });
  const missByApp = new Map((Array.isArray(reply.missing) ? reply.missing : []).filter((m) => m?.app).map((m) => [String(m.app), m]));
  const missing = u.missing.map((m) => {
    const r = missByApp.get(m.appKey);
    const verdict = r?.verdict === "grant" || r?.verdict === "skip" ? r.verdict : u.status === "ACTIVE" ? "grant" : "skip";
    return { appKey: m.appKey, verdict, reason: String(r?.reason ?? `${Math.round(m.cohortShare * 100)}% of the cohort has it.`).slice(0, 300) } as MissingDecision;
  });
  return {
    userId: u.id,
    engine: "llm",
    provider,
    roleAssessment: String(reply.role_assessment ?? base.roleAssessment).slice(0, 400),
    summary: String(reply.summary ?? base.summary).slice(0, 600),
    decisions,
    missing,
    generatedAt: new Date().toISOString(),
  };
}

const cache = new Map<string, UserReview>();

/** Every user's latest review (one per user). */
export function allCachedReviews(): UserReview[] {
  return [...cache.values()];
}

/** Restore saved reviews (e.g. from the last scheduled scan) after a restart. */
export function seedReviewCache(reviews: UserReview[]) {
  for (const r of reviews) {
    if (cachedReview(r.userId)) continue;
    cache.set(`${r.userId}:${r.provider ?? "rules"}`, r);
  }
}

export function cachedReview(userId: number): UserReview | undefined {
  for (const [k, v] of cache) if (k.startsWith(`${userId}:`)) return v;
  return undefined;
}

export async function reviewUser(u: UserDetail, ds: Dataset, llm: LlmProvider | null, force = false): Promise<UserReview> {
  const key = `${u.id}:${llm?.id ?? "rules"}`;
  if (!force && cache.has(key)) return cache.get(key)!;
  let review: UserReview;
  if (!llm) {
    review = rulesReview(u, ds);
  } else {
    try {
      const reply = await callLlmJson<LlmReply>(llm, {
        system: SYSTEM,
        user: JSON.stringify(buildReviewPayload(u, ds)),
        maxTokens: 2048,
      });
      review = mergeReply(u, ds, reply, llm.id);
    } catch (err) {
      review = rulesReview(u, ds, `Model call failed (${(err as Error).message}); showing rules-only verdicts.`);
    }
  }
  // Keep only the latest review per user.
  for (const k of [...cache.keys()]) if (k.startsWith(`${u.id}:`)) cache.delete(k);
  cache.set(key, review);
  return review;
}
