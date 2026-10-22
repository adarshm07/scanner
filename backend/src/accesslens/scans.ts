import fs from "fs";
import path from "path";
import { Cron } from "croner";
import { LlmProvider, ProviderId, callLlmJson, resolveProvider } from "../llm";
import { Dataset, UserDetail, reloadDataset } from "./data";
import { UserReview, allCachedReviews, reviewUser, seedReviewCache } from "./review";

/**
 * Scheduled access scans. A scan re-reads the Okta data (today: the JSON export; later: a
 * live Okta sync), recomputes the rule findings, runs the AI role check for every user in
 * scope, compares the findings with the previous scan, and asks the model for a short
 * summary of what changed. Runs on a daily, weekly or custom cron schedule, or on demand.
 *
 * State (schedule, run history, latest reviews) lives in ACCESSLENS_STATE_DIR
 * (default backend/.accesslens-state), which is git-ignored.
 */

export type Frequency = "daily" | "weekly" | "custom";

export interface ScanSchedule {
  enabled: boolean;
  frequency: Frequency;
  /** HH:MM, used by daily and weekly. */
  time: string;
  /** 0 = Sunday … 6 = Saturday, used by weekly. */
  weekday: number;
  /** Five-field cron expression, used by custom. */
  cron: string;
  /** IANA time zone the schedule is read in. */
  timezone: string;
  /** Model for the AI role check; "rules" skips the model. */
  provider: ProviderId | "rules";
  /** Which users the AI checks: everyone, or only users with findings. */
  scope: "all" | "flagged";
  updatedAt: string | null;
}

export interface ScanSummary {
  headline: string;
  highlights: string[];
  actions: string[];
  engine: "llm" | "rules";
}

export interface ScanRun {
  id: string;
  trigger: "schedule" | "manual";
  status: "running" | "done" | "failed";
  startedAt: string;
  finishedAt: string | null;
  provider: string;
  scope: "all" | "flagged";
  progress: { done: number; total: number };
  usersTotal: number;
  usersReviewed: number;
  /** Reviews where the model failed and rules were used instead. */
  modelFallbacks: number;
  flaggedUsers: number;
  findingsTotal: number;
  byRule: Record<string, number>;
  verdicts: { keep: number; review: number; revoke: number; grant: number };
  newFindings: FindingRef[];
  resolvedFindings: FindingRef[];
  /** Comparison baseline; null for the first scan. */
  previousRunId: string | null;
  summary: ScanSummary | null;
  error?: string;
  /** Every finding in this scan, kept for the next scan's diff (not sent in lists). */
  findings: FindingRef[];
}

export interface FindingRef {
  key: string;
  userId: number;
  userName: string;
  appKey: string | null;
  appLabel: string | null;
  rule: string;
  riskScore: number;
}

const MAX_RUNS = 60;
const CONCURRENCY = 3;

export const DEFAULT_SCHEDULE: ScanSchedule = {
  enabled: false,
  frequency: "daily",
  time: "09:00",
  weekday: 1,
  cron: "0 9 * * 1-5",
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  provider: "rules",
  scope: "all",
  updatedAt: null,
};

function stateDir() {
  const dir = process.env.ACCESSLENS_STATE_DIR?.trim() || path.resolve(__dirname, "../../.accesslens-state");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function readJson<T>(name: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(path.join(stateDir(), name), "utf8")) as T;
  } catch {
    return fallback;
  }
}

function writeJson(name: string, value: unknown) {
  const file = path.join(stateDir(), name);
  fs.writeFileSync(`${file}.tmp`, JSON.stringify(value, null, 2));
  fs.renameSync(`${file}.tmp`, file);
}

// ---------------------------------------------------------------- schedule

/** The cron expression a schedule runs on. */
export function cronFor(s: Pick<ScanSchedule, "frequency" | "time" | "weekday" | "cron">): string {
  if (s.frequency === "custom") return s.cron.trim();
  const [h, m] = s.time.split(":").map(Number);
  return s.frequency === "weekly" ? `${m} ${h} * * ${s.weekday}` : `${m} ${h} * * *`;
}

/** Returns an error message, or null when the schedule is valid. */
export function validateSchedule(s: ScanSchedule): string | null {
  if (!["daily", "weekly", "custom"].includes(s.frequency)) return "frequency must be daily, weekly or custom";
  if (s.frequency !== "custom" && !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time)) return "time must be HH:MM (24h)";
  if (s.frequency === "weekly" && !(Number.isInteger(s.weekday) && s.weekday >= 0 && s.weekday <= 6)) return "weekday must be 0-6";
  if (s.frequency === "custom" && s.cron.trim().split(/\s+/).length !== 5) return "custom schedule needs a five-field cron expression";
  if (!["all", "flagged"].includes(s.scope)) return "scope must be all or flagged";
  if (!["rules", "claude", "gemini", "openai"].includes(s.provider)) return "provider must be rules, claude, gemini or openai";
  try {
    Intl.DateTimeFormat(undefined, { timeZone: s.timezone });
  } catch {
    return `unknown time zone ${s.timezone}`;
  }
  try {
    const job = new Cron(cronFor(s), { timezone: s.timezone, paused: true });
    const next = job.nextRuns(2);
    job.stop();
    if (next.length === 2 && next[1].getTime() - next[0].getTime() < 60 * 60 * 1000) {
      return "scans can run at most once an hour";
    }
  } catch (err) {
    return `invalid cron expression: ${(err as Error).message}`;
  }
  return null;
}

let schedule: ScanSchedule = { ...DEFAULT_SCHEDULE, ...readJson<Partial<ScanSchedule>>("schedule.json", {}) };
let job: Cron | null = null;

function arm() {
  job?.stop();
  job = null;
  if (!schedule.enabled || validateSchedule(schedule)) return;
  job = new Cron(cronFor(schedule), { timezone: schedule.timezone, protect: true }, () => {
    startScan("schedule").catch((err) => console.error(`Scheduled access scan failed: ${(err as Error).message}`));
  });
}

export function getSchedule() {
  return { schedule, cron: cronFor(schedule), nextRuns: nextRuns(schedule, 3) };
}

export function nextRuns(s: ScanSchedule, n: number): string[] {
  if (!s.enabled || validateSchedule(s)) return [];
  const j = new Cron(cronFor(s), { timezone: s.timezone, paused: true });
  const runs = j.nextRuns(n).map((d) => d.toISOString());
  j.stop();
  return runs;
}

export function saveSchedule(input: Partial<ScanSchedule>): { error: string } | ReturnType<typeof getSchedule> {
  const next: ScanSchedule = {
    ...schedule,
    ...pick(input),
    updatedAt: new Date().toISOString(),
  };
  const error = validateSchedule(next);
  if (error) return { error };
  schedule = next;
  writeJson("schedule.json", schedule);
  arm();
  return getSchedule();
}

function pick(i: Partial<ScanSchedule>): Partial<ScanSchedule> {
  const out: Partial<ScanSchedule> = {};
  if (typeof i.enabled === "boolean") out.enabled = i.enabled;
  if (typeof i.frequency === "string") out.frequency = i.frequency as Frequency;
  if (typeof i.time === "string") out.time = i.time;
  if (typeof i.weekday === "number") out.weekday = i.weekday;
  if (typeof i.cron === "string") out.cron = i.cron;
  if (typeof i.timezone === "string") out.timezone = i.timezone;
  if (typeof i.provider === "string") out.provider = i.provider as ScanSchedule["provider"];
  if (i.scope === "all" || i.scope === "flagged") out.scope = i.scope;
  return out;
}

// ---------------------------------------------------------------- runs

let runs: ScanRun[] = readJson<ScanRun[]>("runs.json", []).map((r) =>
  // A run still "running" in the file was cut off by a restart.
  r.status === "running" ? { ...r, status: "failed", finishedAt: r.finishedAt ?? r.startedAt, error: "Interrupted by a server restart." } : r
);

export function listRuns() {
  return runs.map(({ findings, ...r }) => r);
}

export function getRun(id: string) {
  const r = runs.find((x) => x.id === id);
  if (!r) return null;
  const { findings, ...rest } = r;
  return rest;
}

export function runningScan() {
  return runs.find((r) => r.status === "running") ?? null;
}

function persistRuns() {
  writeJson("runs.json", runs.slice(0, MAX_RUNS));
}

function findingRefs(ds: Dataset): FindingRef[] {
  const label = new Map(ds.apps.map((a) => [a.key, a.label]));
  const out: FindingRef[] = [];
  const add = (u: UserDetail, appKey: string | null, rule: string, riskScore: number) =>
    out.push({ key: `${u.id}|${appKey ?? "-"}|${rule}`, userId: u.id, userName: u.name, appKey, appLabel: appKey ? label.get(appKey) ?? appKey : null, rule, riskScore });
  for (const u of ds.detail.values()) {
    for (const a of u.access) for (const f of a.findings) add(u, a.appKey, f.rule, f.riskScore);
    for (const f of u.userFindings) add(u, f.appKey, f.rule, f.riskScore);
    for (const m of u.missing) add(u, m.appKey, "MISSING_ACCESS", 0);
  }
  return out;
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>) {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) await fn(items[i++]);
    })
  );
}

/** Starts a scan in the background. Rejects if one is already running. */
export async function startScan(trigger: ScanRun["trigger"], overrides: Partial<Pick<ScanSchedule, "provider" | "scope">> = {}): Promise<ScanRun> {
  const busy = runningScan();
  if (busy) throw Object.assign(new Error("A scan is already running."), { runId: busy.id });
  const provider = overrides.provider ?? schedule.provider;
  const scope = overrides.scope ?? schedule.scope;
  const llm = provider === "rules" ? null : resolveProvider(provider);
  const previous = runs.find((r) => r.status === "done") ?? null;
  const run: ScanRun = {
    id: `scan_${Date.now().toString(36)}`,
    trigger,
    status: "running",
    startedAt: new Date().toISOString(),
    finishedAt: null,
    provider: llm?.id ?? "rules",
    scope,
    progress: { done: 0, total: 0 },
    usersTotal: 0,
    usersReviewed: 0,
    modelFallbacks: 0,
    flaggedUsers: 0,
    findingsTotal: 0,
    byRule: {},
    verdicts: { keep: 0, review: 0, revoke: 0, grant: 0 },
    newFindings: [],
    resolvedFindings: [],
    previousRunId: previous?.id ?? null,
    summary: null,
    findings: [],
  };
  runs.unshift(run);
  persistRuns();
  execute(run, llm, previous).catch((err) => {
    run.status = "failed";
    run.error = (err as Error).message;
    run.finishedAt = new Date().toISOString();
    persistRuns();
  });
  return run;
}

async function execute(run: ScanRun, llm: LlmProvider | null, previous: ScanRun | null) {
  // 1. Sync and recompute findings.
  const ds = reloadDataset();
  const refs = findingRefs(ds);
  const users = [...ds.detail.values()];
  run.usersTotal = users.length;
  run.flaggedUsers = users.filter((u) => u.findingCount > 0 || u.missing.length > 0).length;
  run.findingsTotal = refs.length;
  for (const f of refs) run.byRule[f.rule] = (run.byRule[f.rule] ?? 0) + 1;
  run.findings = refs;

  // 2. Diff against the previous completed scan.
  if (previous) {
    const before = new Set((previous.findings ?? []).map((f) => f.key));
    const now = new Set(refs.map((f) => f.key));
    run.newFindings = refs.filter((f) => !before.has(f.key)).sort((a, b) => b.riskScore - a.riskScore);
    run.resolvedFindings = (previous.findings ?? []).filter((f) => !now.has(f.key));
  }

  // 3. AI role check for every user in scope.
  const scoped = run.scope === "flagged" ? users.filter((u) => u.findingCount > 0 || u.missing.length > 0) : users;
  run.progress = { done: 0, total: scoped.length };
  persistRuns();
  const reviews: UserReview[] = [];
  await pool(scoped, CONCURRENCY, async (u) => {
    const r = await reviewUser(u, ds, llm, true);
    reviews.push(r);
    if (llm && r.engine === "rules") run.modelFallbacks++;
    for (const d of r.decisions) run.verdicts[d.verdict]++;
    run.verdicts.grant += r.missing.filter((m) => m.verdict === "grant").length;
    run.progress.done++;
    if (run.progress.done % 10 === 0) persistRuns();
  });
  run.usersReviewed = reviews.length;
  writeJson("reviews.json", allCachedReviews());

  // 4. Summarise.
  run.summary = await summarise(run, ds, reviews, llm);
  run.status = "done";
  run.finishedAt = new Date().toISOString();
  persistRuns();
}

const RULE_NAMES: Record<string, string> = {
  STALE_ACCOUNT: "stale account",
  UNUSED_ACCESS: "unused access",
  NEVER_USED: "never used",
  OUTLIER_ACCESS: "outlier access",
  MISSING_ACCESS: "missing access",
  DIRECT_ASSIGNMENT: "direct grant",
  PRIVILEGED_ROLE: "privileged role",
  TOXIC_COMBINATION: "separation-of-duties conflict",
};

function rulesSummary(run: ScanRun): ScanSummary {
  const top = Object.entries(run.byRule).sort((a, b) => b[1] - a[1]).slice(0, 3);
  const change = run.previousRunId
    ? `${run.newFindings.length} new and ${run.resolvedFindings.length} resolved since the last scan.`
    : "First scan, so there is nothing to compare with yet.";
  return {
    engine: "rules",
    headline: `${run.findingsTotal} findings across ${run.flaggedUsers} of ${run.usersTotal} users. ${change}`,
    highlights: top.map(([r, n]) => `${n} ${RULE_NAMES[r] ?? r} finding${n === 1 ? "" : "s"}`),
    actions: [
      run.verdicts.revoke ? `Revoke or confirm ${run.verdicts.revoke} app assignments flagged for removal.` : "",
      run.verdicts.review ? `Have managers review ${run.verdicts.review} assignments.` : "",
      run.verdicts.grant ? `Consider granting ${run.verdicts.grant} apps users' cohorts commonly have.` : "",
    ].filter(Boolean),
  };
}

/**
 * Asks the model for a short operator summary. Like the per-user check, the prompt is
 * pseudonymous: role, app and rule only, never names, emails or Okta IDs.
 */
async function summarise(run: ScanRun, ds: Dataset, reviews: UserReview[], llm: LlmProvider | null): Promise<ScanSummary> {
  const fallback = rulesSummary(run);
  if (!llm) return fallback;
  const role = (userId: number) => {
    const u = ds.detail.get(userId);
    return u ? [u.title, u.department, u.team, u.cohort?.label].filter(Boolean).join(" / ") || "unknown role" : "unknown role";
  };
  const sens = new Map(ds.apps.map((a) => [a.key, a.sensitivity]));
  const payload = {
    usersTotal: run.usersTotal,
    flaggedUsers: run.flaggedUsers,
    findingsByRule: run.byRule,
    verdicts: run.verdicts,
    comparedWithPreviousScan: !!run.previousRunId,
    newFindings: run.newFindings.slice(0, 25).map((f) => ({ role: role(f.userId), app: f.appKey, sensitivity: f.appKey ? sens.get(f.appKey) : null, rule: f.rule, risk: f.riskScore })),
    resolvedFindings: run.resolvedFindings.length,
    revokeRecommendations: reviews
      .flatMap((r) => r.decisions.filter((d) => d.verdict === "revoke").map((d) => ({ role: role(r.userId), app: d.appKey, sensitivity: sens.get(d.appKey), reason: d.reason })))
      .sort((a, b) => ["critical", "high", "medium", "low"].indexOf(a.sensitivity ?? "low") - ["critical", "high", "medium", "low"].indexOf(b.sensitivity ?? "low"))
      .slice(0, 25),
  };
  try {
    const reply = await callLlmJson<{ headline?: string; highlights?: string[]; actions?: string[] }>(llm, {
      system:
        "You summarise an automated Okta access review for an IT security lead. Given aggregate findings, what changed since the last scan, " +
        "and the model's revoke recommendations, reply with JSON only: " +
        '{"headline": one sentence, "highlights": up to 4 short bullets on the most important risks or changes, "actions": up to 4 short, concrete next steps}. ' +
        "Prioritise critical and high sensitivity apps, privileged roles and separation-of-duties conflicts. Do not invent numbers.",
      user: JSON.stringify(payload),
      maxTokens: 800,
    });
    if (!reply.headline) return fallback;
    return {
      engine: "llm",
      headline: String(reply.headline),
      highlights: (Array.isArray(reply.highlights) ? reply.highlights : []).map(String).slice(0, 4),
      actions: (Array.isArray(reply.actions) ? reply.actions : []).map(String).slice(0, 4),
    };
  } catch {
    return fallback;
  }
}

/** Call once at server start: restores saved reviews and arms the schedule. */
export function initScans() {
  seedReviewCache(readJson<UserReview[]>("reviews.json", []));
  arm();
  if (job) console.log(`AccessLens scheduled scan armed: ${cronFor(schedule)} (${schedule.timezone}), next ${job.nextRun()?.toISOString()}`);
}
