import { Category, Finding, SEVERITY_RANK, Severity } from "../schema/finding";
import { config } from "../tools/util";

/**
 * Step 2 of the pipeline (Spec Section 5.2): deterministic noise reduction, before any
 * model sees the findings. It works with no AI key at all:
 *
 *   1. Dedupe by finding_id (the same hit reported twice).
 *   2. Collapse code findings that point at the same file and line for the same weakness
 *      (same CWE) from different rules or tools: one issue, not three.
 *   3. Merge the same dependency advisory reported from several manifests (monorepos).
 *   4. Cap code findings in test, fixture, example and vendored paths at low: they don't
 *      run in production. Secrets are exempt, since a real key leaks wherever it's committed.
 *   5. Drop findings below the severity floor, group by category, and sort: severity, then
 *      known-exploited, then exploit probability.
 */

export interface FilteredFindings {
  groups: Map<Category, Finding[]>;
  totalRaw: number;
  totalAfterFilter: number;
  /** What each deterministic step removed or lowered, for the report notes. */
  reductions: FilterReductions;
}

export interface FilterReductions {
  duplicates: number;
  sameLineMerged: number;
  advisoriesMerged: number;
  nonProductionLowered: number;
  belowFloor: number;
}

function belowFloor(finding: Finding, floor: Severity): boolean {
  // Default rule: drop only when both severity AND confidence are low.
  if (floor === "low") {
    return finding.severity === "low" && finding.confidence === "low";
  }
  // Otherwise drop anything strictly below the configured floor severity.
  return SEVERITY_RANK[finding.severity] < SEVERITY_RANK[floor];
}

const isDependency = (f: Finding) => f.skill.startsWith("npm-audit-") || f.skill.startsWith("osv-");
const isSecret = (f: Finding) => f.skill.startsWith("gitleaks");

/** Paths whose code doesn't ship: tests, fixtures, examples, docs, vendored or minified code. */
const NON_PRODUCTION_DIR =
  /(^|\/)(tests?|__tests__|spec|specs|e2e|cypress|playwright|fixtures?|__fixtures__|mocks?|__mocks__|examples?|samples?|demos?|docs?|benchmarks?|vendor|third[_-]party|node_modules|bower_components)\//i;
const NON_PRODUCTION_FILE = /(\.(test|spec|e2e|stories)\.[cm]?[jt]sx?|_test\.(go|py)|\.min\.js|-min\.js)$|(^|\/)test_[^/]+\.py$/i;

export function isNonProductionPath(file: string | undefined): boolean {
  if (!file) return false;
  return NON_PRODUCTION_DIR.test(file) || NON_PRODUCTION_FILE.test(file);
}

const normCwe = (cwe: unknown) => (typeof cwe === "string" ? cwe.match(/CWE-\d+/i)?.[0]?.toUpperCase() : undefined);

function keepStronger(a: Finding, b: Finding): [Finding, Finding] {
  return SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? [b, a] : [a, b];
}

function exploitRank(f: Finding): [number, number] {
  return [f.metadata.kev === true ? 1 : 0, typeof f.metadata.epss === "number" ? f.metadata.epss : -1];
}

export function filterFindings(
  findings: Finding[],
  floor: Severity = config.severityFloor
): FilteredFindings {
  const totalRaw = findings.length;
  const reductions: FilterReductions = {
    duplicates: 0,
    sameLineMerged: 0,
    advisoriesMerged: 0,
    nonProductionLowered: 0,
    belowFloor: 0,
  };

  // 1. Dedupe by finding_id, keeping the highest-severity duplicate.
  const byId = new Map<string, Finding>();
  for (const f of findings) {
    const existing = byId.get(f.finding_id);
    if (!existing || SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity]) {
      byId.set(f.finding_id, f);
    }
  }
  reductions.duplicates = findings.length - byId.size;

  // 2 + 3. Merge findings that describe the same issue.
  const merged = new Map<string, Finding>();
  const mergeKey = (f: Finding): string | null => {
    if (isDependency(f)) {
      const pkg = f.metadata.package;
      return typeof pkg === "string" ? `dep::${pkg}::${f.metadata.version ?? f.metadata.range ?? ""}::${f.rule_id}` : null;
    }
    const cwe = normCwe(f.metadata.cwe);
    if (isSecret(f) || !cwe || !f.location.file || f.location.line_start === undefined) return null;
    return `code::${f.location.file}::${f.location.line_start}::${cwe}`;
  };
  for (const f of byId.values()) {
    const key = mergeKey(f) ?? `id::${f.finding_id}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, f);
      continue;
    }
    const [keep, drop] = keepStronger(existing, f);
    if (key.startsWith("dep::")) {
      reductions.advisoriesMerged++;
      const alsoIn = new Set([...((keep.metadata.alsoIn as string[] | undefined) ?? []), drop.location.file ?? ""]);
      alsoIn.delete("");
      alsoIn.delete(keep.location.file ?? "");
      keep.metadata = { ...keep.metadata, alsoIn: [...alsoIn] };
    } else {
      reductions.sameLineMerged++;
      const also = new Set([...((keep.metadata.alsoReportedBy as string[] | undefined) ?? []), drop.rule_id]);
      keep.metadata = { ...keep.metadata, alsoReportedBy: [...also] };
    }
    merged.set(key, keep);
  }

  // 4. Code that doesn't ship.
  for (const f of merged.values()) {
    if (isDependency(f) || isSecret(f) || !isNonProductionPath(f.location.file)) continue;
    if (f.metadata.nonProductionPath) continue;
    f.metadata = { ...f.metadata, nonProductionPath: true, toolSeverity: f.metadata.toolSeverity ?? f.severity };
    if (f.severity !== "low") {
      f.tool_message += ` This file is test, example or vendored code that doesn't run in production, so it was lowered from ${f.severity} to low.`;
      f.severity = "low";
      reductions.nonProductionLowered++;
    }
  }

  // 5. Floor, group, sort.
  const survivors = [...merged.values()].filter((f) => !belowFloor(f, floor));
  reductions.belowFloor = merged.size - survivors.length;

  const groups = new Map<Category, Finding[]>();
  for (const f of survivors) {
    const list = groups.get(f.category) ?? [];
    list.push(f);
    groups.set(f.category, list);
  }

  for (const list of groups.values()) {
    list.sort((a, b) => {
      const bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (bySeverity) return bySeverity;
      const [ak, ae] = exploitRank(a);
      const [bk, be] = exploitRank(b);
      if (bk !== ak) return bk - ak;
      if (be !== ae) return be - ae;
      // Code before dependency advisories at equal severity: they're the ones only you can fix.
      return Number(isDependency(a)) - Number(isDependency(b));
    });
  }

  return { groups, totalRaw, totalAfterFilter: survivors.length, reductions };
}

/** One-line description of the deterministic noise reduction, or null if nothing changed. */
export function describeReductions(r: FilterReductions): string | null {
  const parts = [
    r.duplicates && `${r.duplicates} duplicate${r.duplicates === 1 ? "" : "s"} removed`,
    r.sameLineMerged && `${r.sameLineMerged} same-line hit${r.sameLineMerged === 1 ? "" : "s"} merged`,
    r.advisoriesMerged && `${r.advisoriesMerged} repeated advisor${r.advisoriesMerged === 1 ? "y" : "ies"} merged`,
    r.nonProductionLowered && `${r.nonProductionLowered} finding${r.nonProductionLowered === 1 ? "" : "s"} in test/example/vendored code lowered to low`,
    r.belowFloor && `${r.belowFloor} below the severity floor dropped`,
  ].filter(Boolean);
  return parts.length ? `Noise filter: ${parts.join(", ")}.` : null;
}
