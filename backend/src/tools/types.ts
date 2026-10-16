import { Finding } from "../schema/finding";

/** Result of one repo scanner: `ran: false` means it produced no trustworthy output. */
export interface ToolRun {
  findings: Finding[];
  ran: boolean;
  error?: string;
  /** Coverage gaps worth showing that don't make the scan incomplete (e.g. a manifest without a lockfile). */
  notes?: string[];
}
