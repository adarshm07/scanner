import { Category, Finding, SEVERITY_RANK, Severity } from "../schema/finding";
import { config } from "../tools/util";

/**
 * Step 2 of the pipeline (Spec Section 5.2): dedupe by finding_id, drop findings
 * below the severity floor (default: drop low severity + low confidence combos),
 * and group the survivors by category.
 */

export interface FilteredFindings {
  groups: Map<Category, Finding[]>;
  totalRaw: number;
  totalAfterFilter: number;
}

function belowFloor(finding: Finding, floor: Severity): boolean {
  // Default rule: drop only when both severity AND confidence are low.
  if (floor === "low") {
    return finding.severity === "low" && finding.confidence === "low";
  }
  // Otherwise drop anything strictly below the configured floor severity.
  return SEVERITY_RANK[finding.severity] < SEVERITY_RANK[floor];
}

export function filterFindings(
  findings: Finding[],
  floor: Severity = config.severityFloor
): FilteredFindings {
  const totalRaw = findings.length;

  // Dedupe by finding_id, keeping the highest-severity duplicate.
  const byId = new Map<string, Finding>();
  for (const f of findings) {
    const existing = byId.get(f.finding_id);
    if (!existing || SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity]) {
      byId.set(f.finding_id, f);
    }
  }

  const survivors = [...byId.values()].filter((f) => !belowFloor(f, floor));

  const groups = new Map<Category, Finding[]>();
  for (const f of survivors) {
    const list = groups.get(f.category) ?? [];
    list.push(f);
    groups.set(f.category, list);
  }

  // Sort each group by severity (desc) for stable, reviewer-friendly output.
  for (const list of groups.values()) {
    list.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  }

  return { groups, totalRaw, totalAfterFilter: survivors.length };
}
