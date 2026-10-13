import { Router, Request, Response } from "express";
import { runRepoPipeline, runDomainPipeline, Scope } from "../orchestrator/runPipeline";
import { generateReport } from "../orchestrator/report";
import { reportStore } from "../store/reportStore";
import { normalizeDomain } from "../tools/util";
import { listProviders, resolveProvider } from "../llm";
import { CHECKS, CHECK_IDS } from "../orchestrator/checks";
import { Severity, SEVERITY_RANK } from "../schema/finding";
import { EmitFn } from "../orchestrator/events";

/**
 * REST endpoints (Build Spec Section 6).
 */

export const router = Router();

function parseFailOn(input: unknown): Severity {
  const v = String(input ?? "high");
  return (v in SEVERITY_RANK ? v : "high") as Severity;
}

function parseScope(input: unknown, mode: "repo" | "domain"): Scope | null {
  if (input === "all" || input === undefined || input === null) return "all";
  if (Array.isArray(input)) {
    const modeIds = new Set(CHECKS.filter((c) => c.mode === mode).map((c) => c.id));
    const valid = input.filter(
      (c): c is string => typeof c === "string" && CHECK_IDS.has(c) && modeIds.has(c)
    );
    if (valid.length === 0) return null;
    return valid;
  }
  return null;
}

// POST /api/scan/repo
router.post("/scan/repo", async (req: Request, res: Response) => {
  const { repoUrl, checks, provider, failOn, triage, fullHistory } = req.body ?? {};
  if (typeof repoUrl !== "string" || !/^https?:\/\/|^git@/.test(repoUrl)) {
    return res.status(400).json({ error: "Valid repoUrl is required." });
  }
  const parsedScope = parseScope(checks, "repo");
  if (!parsedScope) {
    return res.status(400).json({ error: "Select at least one check." });
  }

  // Triage off forces deterministic mode regardless of the selected provider.
  const llm =
    triage === false ? null : resolveProvider(typeof provider === "string" ? provider : undefined);
  try {
    const pipeline = await runRepoPipeline(repoUrl, parsedScope, fullHistory === true);
    try {
      const report = await generateReport(pipeline, llm, parseFailOn(failOn));
      reportStore.save(report);
      return res.json({ reportId: report.reportId });
    } finally {
      await pipeline.cleanup();
    }
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message });
  }
});

// POST /api/scan/domain
router.post("/scan/domain", async (req: Request, res: Response) => {
  const { domain, attested, checks, provider, failOn, triage } = req.body ?? {};
  if (attested !== true) {
    return res
      .status(403)
      .json({ error: "Attestation required: you must confirm authorization to test this domain." });
  }
  let host: string;
  try {
    host = normalizeDomain(String(domain ?? ""));
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }
  const parsedScope = parseScope(checks, "domain");
  if (!parsedScope) {
    return res.status(400).json({ error: "Select at least one check." });
  }

  const llm =
    triage === false ? null : resolveProvider(typeof provider === "string" ? provider : undefined);
  try {
    const pipeline = await runDomainPipeline(host, parsedScope);
    const report = await generateReport(pipeline, llm, parseFailOn(failOn));
    reportStore.save(report);
    return res.json({ reportId: report.reportId });
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/report/:reportId
router.get("/report/:reportId", (req: Request, res: Response) => {
  const report = reportStore.get(req.params.reportId);
  if (!report) {
    return res.status(404).json({ error: "Report not found." });
  }
  return res.json(report);
});

// GET /api/models — LLM providers for the model selector.
router.get("/models", (_req: Request, res: Response) => {
  return res.json({ providers: listProviders() });
});

// GET /api/checks — per-tool checks for the scope selector.
router.get("/checks", (_req: Request, res: Response) => {
  return res.json({ checks: CHECKS });
});

// --- SSE streaming scans (live progress screen) ---

function openSse(res: Response): EmitFn {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  return (event) => res.write(`data: ${JSON.stringify(event)}\n\n`);
}

function stepsFor(mode: "repo" | "domain", scope: Scope) {
  return CHECKS.filter(
    (c) => c.mode === mode && (scope === "all" || scope.includes(c.id))
  ).map((c) => ({ id: c.id, name: c.name, tools: c.tools }));
}

// POST /api/scan/repo/stream
router.post("/scan/repo/stream", async (req: Request, res: Response) => {
  const { repoUrl, checks, provider, failOn, triage, fullHistory } = req.body ?? {};
  if (typeof repoUrl !== "string" || !/^https?:\/\/|^git@/.test(repoUrl)) {
    return res.status(400).json({ error: "Valid repoUrl is required." });
  }
  const scope = parseScope(checks, "repo");
  if (!scope) return res.status(400).json({ error: "Select at least one check." });

  const emit = openSse(res);
  const llm = triage === false ? null : resolveProvider(typeof provider === "string" ? provider : undefined);
  emit({ t: "start", mode: "repo", target: repoUrl, startedAt: Date.now(), steps: stepsFor("repo", scope) });
  try {
    const pipeline = await runRepoPipeline(repoUrl, scope, fullHistory === true, emit);
    try {
      const report = await generateReport(pipeline, llm, parseFailOn(failOn), emit);
      reportStore.save(report);
      emit({ t: "done", reportId: report.reportId, at: Date.now(), raw: report.stats.totalRaw, findings: report.stats.totalAfterFilter });
    } finally {
      await pipeline.cleanup();
    }
  } catch (err) {
    emit({ t: "error", message: (err as Error).message });
  }
  res.end();
});

// POST /api/scan/domain/stream
router.post("/scan/domain/stream", async (req: Request, res: Response) => {
  const { domain, attested, checks, provider, failOn, triage } = req.body ?? {};
  if (attested !== true) {
    return res.status(403).json({ error: "Attestation required." });
  }
  let host: string;
  try {
    host = normalizeDomain(String(domain ?? ""));
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }
  const scope = parseScope(checks, "domain");
  if (!scope) return res.status(400).json({ error: "Select at least one check." });

  const emit = openSse(res);
  const llm = triage === false ? null : resolveProvider(typeof provider === "string" ? provider : undefined);
  emit({ t: "start", mode: "domain", target: host, startedAt: Date.now(), steps: stepsFor("domain", scope) });
  try {
    const pipeline = await runDomainPipeline(host, scope, emit);
    const report = await generateReport(pipeline, llm, parseFailOn(failOn), emit);
    reportStore.save(report);
    emit({ t: "done", reportId: report.reportId, at: Date.now(), raw: report.stats.totalRaw, findings: report.stats.totalAfterFilter });
  } catch (err) {
    emit({ t: "error", message: (err as Error).message });
  }
  res.end();
});
