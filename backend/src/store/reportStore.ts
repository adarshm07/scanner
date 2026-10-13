import { Report, TriageResult } from "../schema/finding";

/**
 * In-memory store (Build Spec allows in-memory for the hackathon).
 *
 * - reports: assembled reports keyed by reportId.
 * - triageCache: TriageResult keyed by finding_id, so re-running on an unchanged
 *   file/domain skips the LLM call entirely (Spec Section 5.4).
 */

const reports = new Map<string, Report>();
const triageCache = new Map<string, TriageResult>();

export const reportStore = {
  save(report: Report): void {
    reports.set(report.reportId, report);
  },
  get(reportId: string): Report | undefined {
    return reports.get(reportId);
  },
  list(): Report[] {
    return [...reports.values()];
  },
};

export const triageStore = {
  get(findingId: string): TriageResult | undefined {
    return triageCache.get(findingId);
  },
  set(result: TriageResult): void {
    triageCache.set(result.finding_id, result);
  },
  has(findingId: string): boolean {
    return triageCache.has(findingId);
  },
};
