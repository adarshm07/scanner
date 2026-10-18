import { runNpmAudit } from "./npmAudit";
import { runOsvScanner } from "./osvScanner";
import { ToolRun } from "./types";
import { enrichWithExploitIntel } from "./exploitIntel";
import { enrichWithUsage } from "./depUsage";

/**
 * The "Dependencies" check: npm audit for npm projects, OSV-Scanner for everything else
 * (Python, Java, Rust, Go, Ruby, PHP, .NET, yarn/pnpm, ...). Both run in parallel; the
 * check counts as scanned only if every ecosystem present was actually scanned.
 */
export async function runDependencyScan(repoDir: string): Promise<ToolRun> {
  const [npm, osv] = await Promise.all([runNpmAudit(repoDir), runOsvScanner(repoDir)]);
  const errors = [
    npm.ran ? null : npm.error && `npm: ${npm.error}`,
    osv.ran ? null : osv.error && `osv-scanner: ${osv.error}`,
  ].filter((e): e is string => !!e);
  const findings = [...npm.findings, ...osv.findings];
  // Rank by real-world exploitation (CISA KEV, EPSS). Never fails the scan.
  const intel = await enrichWithExploitIntel(findings);
  // Where the app loads each package: evidence for AI reachability, and a cap for never-loaded ones.
  const usage = await enrichWithUsage(repoDir, findings);
  const usageNote = usage.lowered
    ? [`${usage.lowered} production ${usage.lowered === 1 ? "advisory is" : "advisories are"} for packages the app's code and scripts never load, so ${usage.lowered === 1 ? "it was" : "they were"} lowered one level.`]
    : [];
  return {
    findings,
    ran: npm.ran && osv.ran,
    error: errors.join("; ") || undefined,
    notes: [...(npm.notes ?? []), ...(osv.notes ?? []), ...intel.notes, ...usageNote],
  };
}
