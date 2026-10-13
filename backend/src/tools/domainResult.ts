import { CheckResult, Finding } from "../schema/finding";

/** Domain tools report both problems (findings) and every probe run (checks). */
export interface DomainResult {
  findings: Finding[];
  checks: CheckResult[];
}
