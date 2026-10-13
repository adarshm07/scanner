import { Report, TriageResult } from "../schema/finding";

/**
 * In-memory store (Build Spec allows in-memory for the hackathon).
 *
 * - reports: assembled reports keyed by reportId.
 * - triageCache: TriageResult keyed by finding_id, so re-running on an unchanged
 *   file/domain skips the LLM call entirely (Spec Section 5.4).
 */

const REPORT_TTL_MS = Number(process.env.REPORT_TTL_MS) || 24 * 60 * 60 * 1000;
const REPORT_MAX = Number(process.env.REPORT_MAX) || 500;
const TRIAGE_MAX = 5000;

const reports = new Map<string, { report: Report; savedAt: number }>();
const triageCache = new Map<string, TriageResult>();

function isExpired(savedAt: number, now = Date.now()): boolean {
  return now - savedAt > REPORT_TTL_MS;
}

export const reportStore = {
  save(report: Report): void {
    const now = Date.now();
    // Map iterates in insertion order, so the first entries are the oldest.
    for (const [id, entry] of reports) {
      if (!isExpired(entry.savedAt, now) && reports.size < REPORT_MAX) break;
      reports.delete(id);
    }
    reports.set(report.reportId, { report, savedAt: now });
  },
  get(reportId: string): Report | undefined {
    const entry = reports.get(reportId);
    if (!entry) return undefined;
    if (isExpired(entry.savedAt)) {
      reports.delete(reportId);
      return undefined;
    }
    return entry.report;
  },
  list(): Report[] {
    return [...reports.values()].filter((e) => !isExpired(e.savedAt)).map((e) => e.report);
  },
};

export const triageStore = {
  get(findingId: string): TriageResult | undefined {
    return triageCache.get(findingId);
  },
  set(result: TriageResult): void {
    triageCache.delete(result.finding_id);
    if (triageCache.size >= TRIAGE_MAX) {
      const oldest = triageCache.keys().next().value;
      if (oldest !== undefined) triageCache.delete(oldest);
    }
    triageCache.set(result.finding_id, result);
  },
  has(findingId: string): boolean {
    return triageCache.has(findingId);
  },
};
