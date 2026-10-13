import { Finding } from "../schema/finding";

/** Result of one repo scanner: `ran: false` means it produced no trustworthy output. */
export interface ToolRun {
  findings: Finding[];
  ran: boolean;
  error?: string;
}
