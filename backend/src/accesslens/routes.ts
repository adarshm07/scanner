import { Router, Request, Response } from "express";
import { resolveProvider } from "../llm";
import { runRepoPipeline } from "../orchestrator/runPipeline";
import { generateReport } from "../orchestrator/report";
import { reportStore } from "../store/reportStore";
import { resetGitCredentials } from "../tools/gitAuth";
import { getDataset, loadUserGitHubCredentials } from "./data";
import { cachedReview, reviewUser } from "./review";
import { ScanSchedule, getRun, getSchedule, listRuns, saveSchedule, startScan } from "./scans";

const PROVIDERS = ["rules", "claude", "gemini", "openai"];

/**
 * AccessLens API (dummy Okta data). Mounted at /api/accesslens.
 *   GET  /summary            tenant, counts, apps
 *   GET  /dashboard          flat users, assignments and findings for the dashboard
 *   GET  /users              user list with access counts and risk
 *   GET  /users/:id          one user's apps, access type, usage, findings, missing apps
 *   POST /users/:id/review   AI (or rules-only) verdict per app; body { provider?, force? }
 *   GET  /schedule           scheduled scan settings, cron and next run times
 *   PUT  /schedule           update them; body Partial<ScanSchedule>
 *   GET  /scans              scan history, newest first
 *   GET  /scans/:id          one scan with its new / resolved findings and summary
 *   POST /scans              start a scan now; body { provider?, scope? }
 */
export const accessLensRouter = Router();

function loadOr500(res: Response) {
  try {
    return getDataset();
  } catch (err) {
    res.status(500).json({ error: `AccessLens data could not be loaded: ${(err as Error).message}` });
    return null;
  }
}

accessLensRouter.get("/summary", (_req: Request, res: Response) => {
  const ds = loadOr500(res);
  if (!ds) return;
  const statusCounts: Record<string, number> = {};
  for (const u of ds.users) statusCounts[u.status] = (statusCounts[u.status] ?? 0) + 1;
  const ruleCounts: Record<string, number> = {};
  for (const d of ds.detail.values()) {
    for (const a of d.access) for (const f of a.findings) ruleCounts[f.rule] = (ruleCounts[f.rule] ?? 0) + 1;
    for (const f of d.userFindings) ruleCounts[f.rule] = (ruleCounts[f.rule] ?? 0) + 1;
    if (d.missing.length) ruleCounts.MISSING_ACCESS = (ruleCounts.MISSING_ACCESS ?? 0) + d.missing.length;
  }
  res.json({
    tenant: ds.tenant,
    userCount: ds.users.length,
    appCount: ds.apps.length,
    assignmentCount: ds.users.reduce((s, u) => s + u.appCount, 0),
    statusCounts,
    ruleCounts,
    apps: ds.apps.map((a) => ({ key: a.key, label: a.label, sensitivity: a.sensitivity })),
  });
});

accessLensRouter.get("/users", (_req: Request, res: Response) => {
  const ds = loadOr500(res);
  if (!ds) return;
  res.json({
    users: ds.users.map((u) => {
      const r = cachedReview(u.id);
      return {
        ...u,
        review: r
          ? {
              engine: r.engine,
              keep: r.decisions.filter((d) => d.verdict === "keep").length,
              review: r.decisions.filter((d) => d.verdict === "review").length,
              revoke: r.decisions.filter((d) => d.verdict === "revoke").length,
            }
          : null,
      };
    }),
  });
});

/**
 * Everything the dashboard needs in one flat, compact payload. The frontend filters
 * (team, status, type, app, inactivity days) and aggregates client-side, so changing a
 * filter never needs another round trip. Day counts are relative to the last sync.
 */
accessLensRouter.get("/dashboard", (_req: Request, res: Response) => {
  const ds = loadOr500(res);
  if (!ds) return;
  const assignments: {
    userId: number;
    appKey: string;
    daysSinceUse: number | null;
    assignedDays: number | null;
    ssoCount90d: number;
    source: "GROUP" | "DIRECT";
    rules: string[];
  }[] = [];
  const findings: { userId: number; appKey: string | null; rule: string; riskScore: number; explanation: string }[] = [];
  for (const d of ds.detail.values()) {
    for (const a of d.access) {
      assignments.push({
        userId: d.id,
        appKey: a.appKey,
        daysSinceUse: a.daysSinceUse,
        assignedDays: a.assignedDays,
        ssoCount90d: a.ssoCount90d,
        source: a.source,
        rules: a.findings.map((f) => f.rule),
      });
      for (const f of a.findings) {
        findings.push({ userId: d.id, appKey: a.appKey, rule: f.rule, riskScore: f.riskScore, explanation: f.explanation });
      }
    }
    for (const f of d.userFindings) {
      findings.push({ userId: d.id, appKey: f.appKey, rule: f.rule, riskScore: f.riskScore, explanation: f.explanation });
    }
    for (const m of d.missing) {
      findings.push({
        userId: d.id,
        appKey: m.appKey,
        rule: "MISSING_ACCESS",
        riskScore: 0,
        explanation: `${Math.round(m.cohortShare * 100)}% of the ${d.cohort?.label ?? "cohort"} cohort has ${m.appLabel}`,
      });
    }
  }
  res.json({
    tenant: ds.tenant,
    asOf: ds.now.toISOString(),
    thresholds: ds.thresholds,
    apps: ds.apps.map((a) => ({ key: a.key, label: a.label, sensitivity: a.sensitivity })),
    users: ds.users.map((u) => {
      const r = cachedReview(u.id);
      return {
        ...u,
        review: r
          ? {
              engine: r.engine,
              keep: r.decisions.filter((x) => x.verdict === "keep").length,
              review: r.decisions.filter((x) => x.verdict === "review").length,
              revoke: r.decisions.filter((x) => x.verdict === "revoke").length,
            }
          : null,
      };
    }),
    assignments,
    findings,
  });
});

function userFrom(req: Request, res: Response) {
  const ds = loadOr500(res);
  if (!ds) return null;
  const id = Number(req.params.id);
  const user = Number.isInteger(id) ? ds.detail.get(id) : undefined;
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return null;
  }
  return { ds, user };
}

accessLensRouter.get("/users/:id", (req: Request, res: Response) => {
  const found = userFrom(req, res);
  if (!found) return;
  res.json({ user: found.user, review: cachedReview(found.user.id) ?? null });
});

accessLensRouter.post("/users/:id/review", async (req: Request, res: Response) => {
  const found = userFrom(req, res);
  if (!found) return;
  const { provider, force } = req.body ?? {};
  const llm = provider === "rules" ? null : resolveProvider(typeof provider === "string" ? provider : undefined);
  const review = await reviewUser(found.user, found.ds, llm, force === true);
  res.json({ review });
});

accessLensRouter.post("/users/:id/scan-github", async (req: Request, res: Response) => {
  const found = userFrom(req, res);
  if (!found) return;
  const userGitHub = loadUserGitHubCredentials(found.user.id);
  if (!userGitHub) {
    return res.status(400).json({ error: "This user has no GitHub PAT configured in the AccessLens JSON dataset." });
  }
  const repoUrl = userGitHub.repoUrl;
  const previousGitHubToken = process.env.GITHUB_TOKEN;
  const previousGitHubOwners = process.env.GITHUB_OWNERS;
  process.env.GITHUB_TOKEN = userGitHub.token;
  process.env.GITHUB_OWNERS = userGitHub.owner;
  resetGitCredentials();
  try {
    const pipeline = await runRepoPipeline(repoUrl, ["secrets", "sast", "deps"], { fullHistory: false });
    try {
      const report = await generateReport(pipeline, null, "high");
      reportStore.save(report);
      return res.json({ reportId: report.reportId, repoUrl, report });
    } finally {
      await pipeline.cleanup();
    }
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message });
  } finally {
    if (previousGitHubToken === undefined) delete process.env.GITHUB_TOKEN; else process.env.GITHUB_TOKEN = previousGitHubToken;
    if (previousGitHubOwners === undefined) delete process.env.GITHUB_OWNERS; else process.env.GITHUB_OWNERS = previousGitHubOwners;
    resetGitCredentials();
  }
});

accessLensRouter.get("/schedule", (_req: Request, res: Response) => {
  res.json(getSchedule());
});

accessLensRouter.put("/schedule", (req: Request, res: Response) => {
  const result = saveSchedule(req.body ?? {});
  if ("error" in result) return res.status(400).json(result);
  res.json(result);
});

accessLensRouter.get("/scans", (_req: Request, res: Response) => {
  res.json({ runs: listRuns() });
});

accessLensRouter.get("/scans/:id", (req: Request, res: Response) => {
  const run = getRun(req.params.id);
  if (!run) return res.status(404).json({ error: "Scan not found" });
  res.json({ run });
});

accessLensRouter.post("/scans", async (req: Request, res: Response) => {
  const { provider, scope } = req.body ?? {};
  try {
    const run = await startScan("manual", {
      ...(PROVIDERS.includes(provider) ? { provider: provider as ScanSchedule["provider"] } : {}),
      ...(scope === "all" || scope === "flagged" ? { scope } : {}),
    });
    const { findings, ...rest } = run;
    res.status(202).json({ run: rest });
  } catch (err) {
    res.status(409).json({ error: (err as Error).message, runId: (err as { runId?: string }).runId });
  }
});
