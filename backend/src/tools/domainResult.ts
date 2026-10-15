import { CheckResult, Finding } from "../schema/finding";

/** Domain tools report both problems (findings) and every probe run (checks). */
export interface DomainResult {
  findings: Finding[];
  checks: CheckResult[];
  /** Non-failing context for the report, e.g. a check that was inconclusive. */
  notes?: string[];
}
