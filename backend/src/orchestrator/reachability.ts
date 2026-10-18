import { Finding, ReportFinding, SEVERITY_RANK, Severity, TriageResult } from "../schema/finding";
import type { DependencyUsage } from "../tools/depUsage";

/**
 * Dependency reachability: the AI's call on whether the app can actually reach the vulnerable
 * code in a package, given the advisory and the import sites the scanner found.
 *
 * The model only judges; these rules decide what its judgement is allowed to do, so the
 * built-in triage and the coding agent's verdicts (apply-triage) behave the same way:
 * - not_reachable: lowered to low (medium for CISA KEV entries). Still listed, never removed.
 * - reachable: never rated below what the scanner gave it.
 * - unknown: at most one level below the scanner's rating.
 * A dependency advisory is never dropped as a false positive: the vulnerable version is really
 * installed, so a "false_positive" verdict is treated as not_reachable.
 */

export type Reachability = "reachable" | "not_reachable" | "unknown";
export const REACHABILITY: Reachability[] = ["reachable", "not_reachable", "unknown"];

const DOWN: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "low" };
const max = (a: Severity, b: Severity): Severity => (SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b);
const min = (a: Severity, b: Severity): Severity => (SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b);

export function isDependency(f: Pick<Finding, "category" | "skill">): boolean {
  return f.category === "dependencies" || /^(npm-audit|osv)-/.test(f.skill);
}

export function enforceReachability(f: Finding, r: TriageResult): TriageResult {
  if (!isDependency(f)) return r;
  let reachability: Reachability = REACHABILITY.includes(r.reachability as Reachability)
    ? (r.reachability as Reachability)
    : "unknown";
  let verdict = r.verdict;
  if (verdict === "false_positive") {
    verdict = "true_positive";
    reachability = "not_reachable";
  }
  const scanner = f.severity;
  const proposed = SEVERITY_RANK[r.adjusted_severity] ? r.adjusted_severity : scanner;
  let adjusted: Severity;
  if (reachability === "not_reachable") {
    // Known-exploited advisories stay visible at medium even when unreachable.
    adjusted = f.metadata?.kev ? "medium" : "low";
  } else if (reachability === "reachable") {
    adjusted = max(proposed, scanner);
  } else {
    adjusted = max(proposed, DOWN[scanner]);
  }
  // Dev-only packages were capped at low by the scanner; reachability never raises them.
  if (f.metadata?.devOnly) adjusted = min(adjusted, "low");
  return { ...r, verdict, reachability, adjusted_severity: adjusted };
}

export type DependencyBucket = "reachable" | "review" | "not_reachable" | "not_loaded" | "dev_only";

export const BUCKET_LABEL: Record<DependencyBucket, string> = {
  reachable: "Reachable: the app uses the vulnerable code",
  review: "Used by the app, reachability not confirmed",
  not_reachable: "Used, but the vulnerable code isn't reachable",
  not_loaded: "Installed, but never loaded by the app",
  dev_only: "Dev/test tooling only (doesn't ship)",
};

export const BUCKET_ORDER: DependencyBucket[] = ["reachable", "review", "not_reachable", "not_loaded", "dev_only"];

export function dependencyBucket(f: ReportFinding): DependencyBucket {
  if (f.metadata?.devOnly) return "dev_only";
  const reach = f.triage?.reachability;
  if (reach === "reachable") return "reachable";
  if (reach === "not_reachable") {
    const usage = f.metadata?.usage as DependencyUsage | undefined;
    return usage?.status === "not_found" ? "not_loaded" : "not_reachable";
  }
  const usage = f.metadata?.usage as DependencyUsage | undefined;
  if (usage?.status === "not_found") return "not_loaded";
  return "review";
}

/** One-line summary for the report notes, e.g. "Dependencies: 6 reachable, 12 not reachable, ...". */
export function dependencyNote(findings: ReportFinding[]): string | null {
  const deps = findings.filter(isDependency);
  if (deps.length === 0) return null;
  const counts = new Map<DependencyBucket, number>();
  for (const f of deps) counts.set(dependencyBucket(f), (counts.get(dependencyBucket(f)) ?? 0) + 1);
  const words: Record<DependencyBucket, string> = {
    reachable: "reachable",
    review: "used, not yet confirmed",
    not_reachable: "used but not reachable",
    not_loaded: "never loaded by the app",
    dev_only: "dev-only",
  };
  const parts = BUCKET_ORDER.filter((b) => counts.get(b)).map((b) => `${counts.get(b)} ${words[b]}`);
  return `Dependencies: ${parts.join(", ")}. Only reachable or unconfirmed advisories keep their full severity.`;
}

export const DEPENDENCY_NOTE_PREFIX = "Dependencies: ";
