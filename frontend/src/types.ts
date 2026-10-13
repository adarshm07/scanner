// Mirror of the backend report shape (Build Spec Section 4).

export type Category =
  | "frontend"
  | "backend"
  | "cloud"
  | "architecture"
  | "domain";

export type Severity = "critical" | "high" | "medium" | "low";
export type Verdict = "true_positive" | "false_positive" | "needs_review";

export interface TriageResult {
  finding_id: string;
  verdict: Verdict;
  adjusted_severity: Severity;
  explanation: string;
  suggested_fix: string;
}

export interface ReportFinding {
  skill: string;
  category: Category;
  finding_id: string;
  rule_id: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  title: string;
  location: { file?: string; line_start?: number; line_end?: number; url?: string };
  raw_snippet: string | null;
  tool_message: string;
  metadata: Record<string, unknown>;
  triage: TriageResult | null;
}

export interface CategoryGroup {
  category: Category;
  findings: ReportFinding[];
}

export interface CheckResult {
  group: string;
  name: string;
  result: "pass" | "finding";
  severity?: Severity;
  observed: string;
  remediation?: string;
  source: string;
}

export interface Report {
  reportId: string;
  mode: "repo" | "domain";
  target: string;
  ref: string;
  createdAt: string;
  executiveSummary: string;
  warning?: string;
  categories: CategoryGroup[];
  checks: CheckResult[];
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
    provider: ProviderId | null;
    triageEnabled: boolean;
    llmFallbackUsed: boolean;
  };
}

export interface Check {
  id: string;
  mode: "repo" | "domain";
  name: string;
  tools: string;
  desc: string;
  est: string;
}

export type ScanEvent =
  | { t: "start"; mode: "repo" | "domain"; target: string; startedAt: number; steps: { id: string; name: string; tools: string }[] }
  | { t: "tool"; id: string; status: "running"; at: number }
  | { t: "tool"; id: string; status: "done"; at: number; ms: number; hits: number }
  | { t: "tool"; id: string; status: "error"; at: number; ms: number; hits: number; message: string }
  | { t: "log"; at: number; source: string; message: string }
  | { t: "stage"; id: string; name: string; status: "running" | "done"; at: number; ms?: number; detail?: string }
  | { t: "done"; reportId: string; at: number; raw: number; findings: number }
  | { t: "error"; message: string };

export type ProviderId = "claude" | "gemini";

export interface ProviderDescriptor {
  id: ProviderId;
  label: string;
  model: string;
  enabled: boolean;
  available: boolean;
  isDefault: boolean;
}
