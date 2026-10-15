import path from "path";
import { Report, ReportFinding, Severity } from "../schema/finding";

/**
 * Convert a repo-mode report to SARIF 2.1.0, the format GitHub code scanning (and most
 * other code-review tools) ingest. Findings without a file location (domain mode) are
 * skipped, since SARIF results must point at a file in the repository.
 */

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_VERSION = "0.1.0";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/** GitHub maps this 0-10 score to its own critical/high/medium/low labels. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
};

function severityOf(f: ReportFinding): Severity {
  return f.triage?.adjusted_severity ?? f.severity;
}

/** Repository-relative POSIX path, or null when the file is outside the scanned root. */
export function relativeUri(file: string, roots: string[]): string | null {
  const normalized = file.split(path.sep).join("/");
  if (!path.isAbsolute(file)) return normalized.replace(/^\.\//, "");
  for (const root of roots) {
    const rel = path.relative(root, file);
    if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) return rel.split(path.sep).join("/");
  }
  return null;
}

function messageFor(f: ReportFinding): { text: string; markdown: string } {
  const parts = [f.triage?.explanation || f.tool_message];
  const md = [`**${f.title}**`, "", f.triage?.explanation || f.tool_message];
  if (f.triage?.suggested_fix) {
    parts.push(`Fix: ${f.triage.suggested_fix}`);
    md.push("", "**Fix**", "", f.triage.suggested_fix);
  }
  if (f.triage && f.triage.verdict !== "true_positive") {
    const v = f.triage.verdict.replace("_", " ");
    parts.push(`Triage verdict: ${v}.`);
    md.push("", `_Triage verdict: ${v}._`);
  }
  return { text: parts.join("\n\n"), markdown: md.join("\n") };
}

export function toSarif(report: Report, repoRoots: string[]): Record<string, unknown> {
  const findings = report.categories.flatMap((c) => c.findings);
  const rules = new Map<string, Record<string, unknown>>();
  const results: Record<string, unknown>[] = [];

  for (const f of findings) {
    if (!f.location.file) continue;
    const uri = relativeUri(f.location.file, repoRoots);
    if (!uri) continue;
    const severity = severityOf(f);
    // `skill` is stable and readable (e.g. "semgrep-...", "gitleaks-...", "npm-audit-<pkg>").
    const ruleId = f.skill;
    const existing = rules.get(ruleId);
    const helpUri =
      typeof f.metadata?.advisoryUrl === "string"
        ? f.metadata.advisoryUrl
        : /^https?:\/\//.test(f.rule_id)
          ? f.rule_id
          : undefined;
    const tags = ["security", f.category];
    if (typeof f.metadata?.cwe === "string") tags.push(f.metadata.cwe);
    // Keep the highest severity seen for a rule.
    if (!existing || Number(SECURITY_SEVERITY[severity]) > Number((existing.properties as Record<string, string>)["security-severity"])) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: f.title },
        fullDescription: { text: f.tool_message },
        ...(helpUri ? { helpUri } : {}),
        defaultConfiguration: { level: LEVEL[severity] },
        properties: {
          tags,
          precision: f.confidence === "high" ? "high" : f.confidence === "medium" ? "medium" : "low",
          "security-severity": SECURITY_SEVERITY[severity],
        },
      });
    }

    const startLine = f.location.line_start && f.location.line_start > 0 ? f.location.line_start : 1;
    const endLine = f.location.line_end && f.location.line_end >= startLine ? f.location.line_end : startLine;
    results.push({
      ruleId,
      level: LEVEL[severity],
      message: messageFor(f),
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
            region: { startLine, endLine },
          },
        },
      ],
      partialFingerprints: { "scannerX/v1": f.finding_id },
      properties: {
        scanner: f.skill.split("-")[0],
        confidence: f.confidence,
        ...(f.triage ? { verdict: f.triage.verdict } : {}),
        ...(f.metadata?.lockfileGenerated ? { lockfileGenerated: true } : {}),
      },
    });
  }

  const notifications = [report.warning, ...(report.notes ?? [])]
    .filter((m): m is string => !!m)
    .map((text) => ({ level: text === report.warning ? "error" : "note", message: { text } }));

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Scanner-X",
            informationUri: "https://github.com/adarshm07/scanner",
            semanticVersion: TOOL_VERSION,
            rules: [...rules.values()],
          },
        },
        automationDetails: { id: `scanner-x/${report.diff ? "diff" : "full"}/` },
        invocations: [
          {
            executionSuccessful: !report.policy.reason,
            ...(notifications.length ? { toolExecutionNotifications: notifications } : {}),
          },
        ],
        results,
      },
    ],
  };
}
