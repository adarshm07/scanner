import { CheckResult, Finding } from "../schema/finding";
import type { FixInput } from "./fixConfig";

/** Domain tools report both problems (findings) and every probe run (checks). */
export interface DomainResult {
  findings: Finding[];
  checks: CheckResult[];
  /** Non-failing context for the report, e.g. a check that was inconclusive. */
  notes?: string[];
  /** Header check only: what the copy-paste fix snippets need to cover. */
  fix?: FixInput;
}
