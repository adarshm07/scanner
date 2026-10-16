import { runNpmAudit } from "./npmAudit";
import { runOsvScanner } from "./osvScanner";
import { ToolRun } from "./types";

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
  return {
    findings: [...npm.findings, ...osv.findings],
    ran: npm.ran && osv.ran,
    error: errors.join("; ") || undefined,
    notes: [...(npm.notes ?? []), ...(osv.notes ?? [])],
  };
}
