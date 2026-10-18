import type { FixPlan } from "../tools/fixConfig";
import { createHash } from "crypto";

/**
 * The universal finding schema (Build Spec Section 4).
 *
 * Every deterministic tool adapter must transform its native output into this
 * exact shape before it enters the pipeline. This is the contract that keeps the
 * LLM layer cheap and tool-agnostic.
 */

export type Category =
  | "frontend"
  | "backend"
  | "cloud"
  | "architecture"
  | "domain"
  /** Vulnerable packages (npm audit, OSV-Scanner), kept apart from the app's own code findings. */
  | "dependencies";

export type Severity = "critical" | "high" | "medium" | "low";

export type Confidence = "high" | "medium" | "low";

export interface FindingLocation {
  file?: string; // repo mode
  line_start?: number;
  line_end?: number;
  url?: string; // domain mode
}

export interface FindingMetadata {
  cwe?: string;
  owasp?: string;
  [key: string]: unknown;
}

export interface Finding {
  skill: string; // e.g. "semgrep-sql-injection"
  category: Category;
  finding_id: string; // stable hash of file+line+rule_id (or domain+check)
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  location: FindingLocation;
  /**
   * ALWAYS null when the finding is created. Populated later, only for findings
   * that survive filtering (snippet hydration step).
   */
  raw_snippet: string | null;
  tool_message: string; // the tool's own description, verbatim
  metadata: FindingMetadata;
}

/**
 * LLM triage verdict for a single finding.
 */
export type Verdict = "true_positive" | "false_positive" | "needs_review";

export interface TriageResult {
  finding_id: string;
  verdict: Verdict;
  adjusted_severity: Severity;
  explanation: string;
  suggested_fix: string;
  /**
   * Dependency findings only: can the app reach the vulnerable code? Judged by the AI from the
   * advisory and the import sites in metadata.usage; enforced by orchestrator/reachability.ts.
   */
  reachability?: "reachable" | "not_reachable" | "unknown";
}

/**
 * A finding merged with its triage verdict for the final report.
 */
export interface ReportFinding extends Finding {
  triage: TriageResult | null;
}

export interface CategoryGroup {
  category: Category;
  findings: ReportFinding[];
}

export type ScanMode = "repo" | "domain";

/**
 * One probe a tool actually performed, pass or finding, with the observed value.
 * Powers the domain report's "Checks" table (both passes and findings).
 */
export interface CheckResult {
  group: string; // "TLS", "Certificate & DNS", "HTTP headers", "Email auth (DNS)"
  name: string; // "TLS protocol", "Expiry", "Content-Security-Policy"
  result: "pass" | "finding" | "inconclusive";
  severity?: Severity; // set when result === "finding"
  observed: string; // "TLSv1.3 negotiated", "valid until 2026-11-21 (59 days)"
  remediation?: string;
  source: string; // tool/check id: "tls", "headers", "dns", "subdomains"
}

export interface Report {
  reportId: string;
  mode: ScanMode;
  target: string; // repoUrl or domain
  ref: string; // commit hash or scan timestamp
  createdAt: string;
  executiveSummary: string;
  warning?: string;
  /** Informational notes that don't affect the policy (e.g. an inconclusive check). */
  notes?: string[];
  /** Diff (PR) scans only. */
  diff?: { baseRef: string; baseSha: string; headSha: string; changedFiles: number };
  categories: CategoryGroup[];
  /** Domain scans: copy-paste config for the header, cookie and HTTPS findings. */
  fixes?: FixPlan;
  checks: CheckResult[]; // domain mode: every probe run, pass or finding
  stats: {
    totalRaw: number;
    totalAfterFilter: number;
    bySeverity: Record<Severity, number>;
  };
  policy: {
    failOn: Severity;
    passed: boolean;
    countAtOrAbove: number;
    reason?: string;
  };
  ai: {
    provider: "gemini" | "claude" | "openai" | "agent" | null;
    triageEnabled: boolean;
    llmFallbackUsed: boolean;
  };
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Stable finding id: hash of the identifying coordinates so the same issue on an
 * unchanged file/domain produces the same id (enables triage caching).
 */
export function makeFindingId(parts: {
  file?: string;
  line_start?: number;
  rule_id: string;
  url?: string;
  check?: string;
  domain?: string;
}): string {
  const key = [
    parts.domain ?? "",
    parts.url ?? "",
    parts.check ?? "",
    parts.file ?? "",
    parts.line_start ?? "",
    parts.rule_id,
  ].join("::");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}
