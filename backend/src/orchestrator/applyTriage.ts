import {
  Report,
  ReportFinding,
  Severity,
  SEVERITY_RANK,
  TriageResult,
  Verdict,
} from "../schema/finding";

/**
 * Merge triage verdicts produced outside Scanner-X (e.g. by the coding agent running the
 * skill) into a report, exactly like the built-in LLM triage would: confirmed false
 * positives are removed, severities adjusted, and stats and policy recomputed. This makes
 * an agent-triaged scan produce the same JSON/SARIF as a gateway-triaged one, without
 * Scanner-X needing an API key.
 */

const VERDICTS: Verdict[] = ["true_positive", "false_positive", "needs_review"];
const MAX_TEXT = 4000;

export interface ApplyTriageResult {
  report: Report;
  applied: number;
  removedAsFalsePositive: number;
  unknownIds: string[];
  invalid: string[];
}

function clean(text: unknown): string {
  return typeof text === "string" ? text.trim().slice(0, MAX_TEXT) : "";
}

/** Validate one agent-written entry; returns null (with a reason) when unusable. */
function parseEntry(raw: unknown, current: ReportFinding): TriageResult | string {
  if (!raw || typeof raw !== "object") return "not an object";
  const r = raw as Record<string, unknown>;
  if (!VERDICTS.includes(r.verdict as Verdict)) return `verdict must be one of ${VERDICTS.join(", ")}`;
  const sev = (r.adjusted_severity ?? current.triage?.adjusted_severity ?? current.severity) as Severity;
  if (!(sev in SEVERITY_RANK)) return "adjusted_severity must be critical, high, medium or low";
  const explanation = clean(r.explanation);
  if (!explanation) return "explanation is required";
  return {
    finding_id: current.finding_id,
    verdict: r.verdict as Verdict,
    adjusted_severity: sev,
    explanation,
    suggested_fix: clean(r.suggested_fix),
  };
}

export function applyTriage(
  report: Report,
  entries: unknown,
  opts: { failOn?: Severity } = {}
): ApplyTriageResult {
  const list = Array.isArray(entries)
    ? entries
    : entries && typeof entries === "object" && Array.isArray((entries as { results?: unknown }).results)
      ? (entries as { results: unknown[] }).results
      : null;
  if (!list) throw new Error('triage file must be a JSON array (or { "results": [...] }) of verdicts');

  const byId = new Map<string, ReportFinding>();
  for (const c of report.categories) for (const f of c.findings) byId.set(f.finding_id, f);

  let applied = 0;
  const unknownIds: string[] = [];
  const invalid: string[] = [];
  for (const raw of list) {
    const id = (raw as { finding_id?: unknown })?.finding_id;
    if (typeof id !== "string") {
      invalid.push("entry without finding_id");
      continue;
    }
    const finding = byId.get(id);
    if (!finding) {
      unknownIds.push(id);
      continue;
    }
    const parsed = parseEntry(raw, finding);
    if (typeof parsed === "string") {
      invalid.push(`${id}: ${parsed}`);
      continue;
    }
    finding.triage = parsed;
    applied += 1;
  }

  // Same rule as the built-in triage: confirmed false positives leave the reviewer-facing report.
  let removedAsFalsePositive = 0;
  const categories = report.categories
    .map((c) => {
      const kept = c.findings.filter((f) => f.triage?.verdict !== "false_positive");
      removedAsFalsePositive += c.findings.length - kept.length;
      kept.sort(
        (a, b) =>
          SEVERITY_RANK[b.triage?.adjusted_severity ?? b.severity] -
          SEVERITY_RANK[a.triage?.adjusted_severity ?? a.severity]
      );
      return { ...c, findings: kept };
    })
    .filter((c) => c.findings.length > 0);

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const c of categories) for (const f of c.findings) bySeverity[f.triage?.adjusted_severity ?? f.severity] += 1;
  const total = Object.values(bySeverity).reduce((a, b) => a + b, 0);
  const failOn = opts.failOn ?? report.policy.failOn;
  const countAtOrAbove = (Object.keys(bySeverity) as Severity[])
    .filter((s) => SEVERITY_RANK[s] >= SEVERITY_RANK[failOn])
    .reduce((n, s) => n + bySeverity[s], 0);

  const updated: Report = {
    ...report,
    categories,
    stats: { ...report.stats, totalAfterFilter: total, bySeverity },
    policy: {
      ...report.policy,
      failOn,
      countAtOrAbove,
      passed: countAtOrAbove === 0 && !report.policy.reason,
    },
    ai: {
      provider: "agent",
      triageEnabled: applied > 0,
      llmFallbackUsed: false,
    },
  };
  return { report: updated, applied, removedAsFalsePositive, unknownIds, invalid };
}
