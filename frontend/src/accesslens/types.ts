// Mirror of backend/src/accesslens shapes.
import type { Severity } from "../types";

export type Sensitivity = Severity;
export type AccessVerdict = "keep" | "review" | "revoke";

export interface AlFinding {
  id: number;
  rule: string;
  riskScore: number;
  explanation: string;
  appKey: string | null;
  evidence: Record<string, unknown>;
}

export interface AppAccess {
  appId: number;
  appKey: string;
  appLabel: string;
  sensitivity: Sensitivity;
  signOnMode: string;
  appRoles: string[];
  source: "GROUP" | "DIRECT";
  viaGroup: string | null;
  status: string;
  syncState: string;
  assignedAt: string | null;
  assignedDays: number | null;
  lastSsoAt: string | null;
  daysSinceUse: number | null;
  ssoCount90d: number;
  cohortShare: number | null;
  findings: AlFinding[];
}

export interface MissingApp {
  appKey: string;
  appLabel: string;
  sensitivity: Sensitivity;
  cohortShare: number;
}

export interface GitHubAccessConfig {
  username: string | null;
  owner: string | null;
  repo: string | null;
  repoUrl: string | null;
  tokenConfigured: boolean;
}

export interface AlUserSummary {
  id: number;
  oktaId: string;
  name: string;
  email: string;
  status: string;
  title: string | null;
  department: string | null;
  team: string | null;
  employeeType: string;
  country: string;
  manager: { id: number; name: string } | null;
  created: string | null;
  lastLogin: string | null;
  cohort: { key: string; label: string; confidence: number; similarity: number; isOverride: boolean } | null;
  adminRoles: string[];
  groups: string[];
  appCount: number;
  findingCount: number;
  riskScore: number;
  topRules: string[];
  github: GitHubAccessConfig | null;
  review?: { engine: "llm" | "rules"; keep: number; review: number; revoke: number } | null;
}

export interface AlUserDetail extends AlUserSummary {
  access: AppAccess[];
  missing: MissingApp[];
  userFindings: AlFinding[];
  cohortSize: number;
}

export interface UserReview {
  userId: number;
  engine: "llm" | "rules";
  provider: string | null;
  roleAssessment: string;
  summary: string;
  decisions: { appKey: string; verdict: AccessVerdict; reason: string; confidence: "high" | "medium" | "low"; ruleVerdict: AccessVerdict }[];
  missing: { appKey: string; verdict: "grant" | "skip"; reason: string }[];
  generatedAt: string;
  error?: string;
}

export interface AlSummary {
  tenant: { domain: string; lastSyncAt: string | null };
  userCount: number;
  appCount: number;
  assignmentCount: number;
  statusCounts: Record<string, number>;
  ruleCounts: Record<string, number>;
}
