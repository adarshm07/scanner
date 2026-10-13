import { randomUUID } from "crypto";
import {
  CategoryGroup,
  Report,
  ReportFinding,
  Severity,
  SEVERITY_RANK,
} from "../schema/finding";
import { callLlm, LlmProvider } from "../llm";
import { PipelineOutput } from "./runPipeline";
import { filterFindings } from "./filterFindings";
import { hydrateSnippets } from "./hydrate";
import { triageCategory } from "./triage";
import { EmitFn } from "./events";

/**
 * Step 5 of the pipeline (Spec Section 5.5): assemble the final report in code by
 * merging tool severity + LLM verdict + LLM explanation, then make exactly ONE
 * LLM call to write a short executive summary — the only creative-writing call.
 */

function repoName(target: string): string {
  return target.replace(/\.git$/, "").split("/").filter(Boolean).pop() ?? target;
}

function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

const plural = (n: number, word: string, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

async function executiveSummary(
  provider: LlmProvider | null,
  target: string,
  mode: string,
  categories: CategoryGroup[],
  stats: Report["stats"],
  coverageWarning?: string
): Promise<string> {
  const deterministic = () => {
    const prefix = coverageWarning ? `Coverage incomplete — ${coverageWarning} ` : "";
    const order: Severity[] = ["critical", "high", "medium", "low"];
    const parts = order
      .filter((s) => stats.bySeverity[s] > 0)
      .map((s) => `${stats.bySeverity[s]} ${s}`);
    if (stats.totalAfterFilter === 0) {
      return `${prefix}Scan of ${target} (${mode} mode) surfaced no findings above the configured severity floor.`;
    }
    const topSeverity = order.find((s) => stats.bySeverity[s] > 0);
    return `${prefix}Scan of ${target} (${mode} mode) surfaced ${plural(stats.totalAfterFilter, "finding")} across ${plural(categories.length, "category", "categories")} (${parts.join(", ")}). Review the ${topSeverity} items first.`;
  };

  if (!provider) return deterministic();

  const digest = categories.map((c) => ({
    category: c.category,
    findings: c.findings.map((f) => ({
      title: f.title,
      severity: f.triage?.adjusted_severity ?? f.severity,
      verdict: f.triage?.verdict,
    })),
  }));

  try {
    const summary = await callLlm(provider, {
      system:
        "You are a security lead writing an executive summary for a non-security-specialist reader. In 3-5 plain-language sentences, state the overall risk posture, call out the 1-2 most urgent items, and flag any cross-finding pattern worth noting (e.g. 'several findings point to insufficient input validation across multiple routes' rather than just listing categories). Do not repeat individual finding explanations — synthesize, do not summarize by concatenation.",
      user: `Target: ${target} (${mode} mode). Findings by category:\n${JSON.stringify(
        digest,
        null,
        2
      )}${coverageWarning ? `\nCoverage warning: ${coverageWarning} Say so first.` : ""}`,
      maxTokens: 600,
    });
    return summary.trim();
  } catch {
    // LLM outage shouldn't fail the scan — fall back to the code-generated summary.
    return deterministic();
  }
}

/**
 * Full driver: filter -> hydrate -> triage -> assemble -> executive summary.
 */
export async function generateReport(
  pipeline: PipelineOutput,
  provider: LlmProvider | null,
  failOn: Severity = "high",
  emit: EmitFn = () => {}
): Promise<Report> {
  const dedupStart = Date.now();
  emit({ t: "stage", id: "dedup", name: "Merge hits", status: "running", at: dedupStart });
  const { groups, totalRaw, totalAfterFilter } = filterFindings(
    pipeline.findings
  );
  emit({
    t: "stage",
    id: "dedup",
    name: "Merge hits",
    status: "done",
    at: Date.now(),
    ms: Date.now() - dedupStart,
    detail: `${pipeline.findings.length} hits, ${totalAfterFilter} findings`,
  });

  const name = repoName(pipeline.target);
  const categories: CategoryGroup[] = [];
  const bySeverity = emptySeverityCounts();

  const triageStart = Date.now();
  emit({ t: "stage", id: "triage", name: "Model explanations", status: "running", at: triageStart });
  let llmFallbackUsed = false;

  for (const [category, findings] of groups) {
    // Snippet hydration (repo mode only) — survivors only.
    if (pipeline.mode === "repo" && pipeline.repoDir) {
      await hydrateSnippets(findings, pipeline.repoDir);
    }

    const triageOut = await triageCategory(provider, category, name, findings);
    llmFallbackUsed = llmFallbackUsed || triageOut.llmFallbackUsed;

    const reportFindings: ReportFinding[] = findings
      .map((f) => ({ ...f, triage: triageOut.results.get(f.finding_id) ?? null }))
      // Drop confirmed false positives from the reviewer-facing report.
      .filter((f) => f.triage?.verdict !== "false_positive");

    for (const f of reportFindings) {
      const sev = f.triage?.adjusted_severity ?? f.severity;
      bySeverity[sev] += 1;
    }

    reportFindings.sort((a, b) => {
      const sa = a.triage?.adjusted_severity ?? a.severity;
      const sb = b.triage?.adjusted_severity ?? b.severity;
      return SEVERITY_RANK[sb] - SEVERITY_RANK[sa];
    });

    if (reportFindings.length > 0) {
      categories.push({ category, findings: reportFindings });
    }
  }

  categories.sort((a, b) => {
    const maxSev = (g: CategoryGroup) =>
      Math.max(
        0,
        ...g.findings.map(
          (f) => SEVERITY_RANK[f.triage?.adjusted_severity ?? f.severity]
        )
      );
    return maxSev(b) - maxSev(a);
  });

  const finalAfterFilter = categories.reduce(
    (n, c) => n + c.findings.length,
    0
  );

  emit({
    t: "stage",
    id: "triage",
    name: "Model explanations",
    status: "done",
    at: Date.now(),
    ms: Date.now() - triageStart,
    detail: `${finalAfterFilter} explained`,
  });

  const stats: Report["stats"] = {
    totalRaw,
    totalAfterFilter: finalAfterFilter,
    bySeverity,
  };

  // Fail-on policy: how many findings sit at or above the chosen threshold.
  const countAtOrAbove = (Object.keys(bySeverity) as Severity[])
    .filter((s) => SEVERITY_RANK[s] >= SEVERITY_RANK[failOn])
    .reduce((n, s) => n + bySeverity[s], 0);

  const summary = await executiveSummary(
    provider,
    pipeline.target,
    pipeline.mode,
    categories,
    { ...stats, totalAfterFilter: finalAfterFilter },
    pipeline.incomplete ? pipeline.warning : undefined
  );

  return {
    reportId: randomUUID(),
    mode: pipeline.mode,
    target: pipeline.target,
    ref: pipeline.ref,
    createdAt: new Date().toISOString(),
    executiveSummary: summary,
    warning: pipeline.warning,
    categories,
    checks: pipeline.checks,
    stats,
    policy: {
      failOn,
      passed: countAtOrAbove === 0 && !pipeline.incomplete,
      countAtOrAbove,
      ...(pipeline.incomplete ? { reason: "scan incomplete" } : {}),
    },
    ai: {
      provider: provider?.id ?? null,
      triageEnabled: provider !== null,
      llmFallbackUsed,
    },
  };
}
