import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { CheckResult, Finding, ScanMode } from "../schema/finding";
import { runCommand } from "../tools/util";
import { runGitleaks } from "../tools/gitleaks";
import { runSemgrep } from "../tools/semgrep";
import { runNpmAudit } from "../tools/npmAudit";
import { runTlsCheck } from "../tools/tlsCheck";
import { runHeaderCheck } from "../tools/headerCheck";
import { runCspCheck } from "../tools/cspCheck";
import { runDnsCheck } from "../tools/dnsCheck";
import { runSubdomainCheck } from "../tools/subdomainCheck";
import { runExposedFiles } from "../tools/exposedFiles";
import { DomainResult } from "../tools/domainResult";
import { CHECKS } from "./checks";
import { EmitFn } from "./events";

/**
 * Step 1 of the pipeline (Spec Section 5.1): run the selected per-check tool
 * adapters in parallel and collect Finding[]. Emits real per-tool timing events
 * for the live progress screen.
 */

/** List of check ids to run, or "all". */
export type Scope = string[] | "all";

interface RepoTool {
  check: string;
  run: (repoDir: string) => Promise<Finding[]>;
}

const REPO_TOOLS: RepoTool[] = [
  { check: "secrets", run: runGitleaks },
  { check: "sast", run: runSemgrep },
  { check: "deps", run: runNpmAudit },
];

interface DomainTool {
  check: string;
  run: (host: string) => Promise<DomainResult>;
}

const DOMAIN_TOOLS: DomainTool[] = [
  { check: "tls", run: runTlsCheck },
  { check: "headers", run: runHeaderCheck },
  { check: "csp", run: runCspCheck },
  { check: "dns", run: runDnsCheck },
  { check: "subdomains", run: runSubdomainCheck },
  { check: "exposed-files", run: runExposedFiles },
];

export interface PipelineOutput {
  mode: ScanMode;
  target: string;
  ref: string;
  findings: Finding[];
  checks: CheckResult[]; // domain mode: every probe run, pass or finding
  /** Absolute path to the checked-out repo (repo mode) for snippet hydration. */
  repoDir?: string;
  cleanup: () => Promise<void>;
}

function selected(check: string, scope: Scope): boolean {
  return scope === "all" || scope.includes(check);
}

const noop: EmitFn = () => {};

function checkName(id: string): string {
  return CHECKS.find((c) => c.id === id)?.name ?? id;
}

/** Run one tool with timing + start/done events. */
async function runTracked<T>(
  check: string,
  fn: () => Promise<Finding[]>,
  emit: EmitFn
): Promise<Finding[]> {
  const start = Date.now();
  emit({ t: "tool", id: check, status: "running", at: start });
  const findings = await fn();
  const end = Date.now();
  emit({
    t: "tool",
    id: check,
    status: "done",
    at: end,
    ms: end - start,
    hits: findings.length,
  });
  emit({
    t: "log",
    at: end,
    source: check,
    message: `${checkName(check)}: ${findings.length} ${findings.length === 1 ? "hit" : "hits"}`,
  });
  return findings;
}

async function cloneRepo(repoUrl: string): Promise<{ dir: string; ref: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-"));
  const clone = await runCommand(
    "git",
    ["clone", "--depth", "1", repoUrl, dir],
    { timeoutMs: 120000 }
  );
  let ref = new Date().toISOString();
  if (!clone.spawnError && clone.code === 0) {
    const rev = await runCommand("git", ["rev-parse", "HEAD"], { cwd: dir });
    if (rev.code === 0) ref = rev.stdout.trim();
  }
  return { dir, ref };
}

export async function runRepoPipeline(
  repoUrl: string,
  scope: Scope,
  emit: EmitFn = noop
): Promise<PipelineOutput> {
  let dir: string;
  let ref: string;
  try {
    const cloned = await cloneRepo(repoUrl);
    dir = cloned.dir;
    ref = cloned.ref;
  } catch {
    // Clone failed — run tools against a throwaway dir so demo fallbacks engage.
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-"));
    ref = new Date().toISOString();
  }

  const tools = REPO_TOOLS.filter((t) => selected(t.check, scope));
  const results = await Promise.all(
    tools.map((t) => runTracked(t.check, () => t.run(dir), emit))
  );
  const findings = results.flat();

  return {
    mode: "repo",
    target: repoUrl,
    ref,
    findings,
    checks: [],
    repoDir: dir,
    cleanup: async () => {
      await fs.rm(dir, { recursive: true, force: true });
    },
  };
}

export async function runDomainPipeline(
  host: string,
  scope: Scope,
  emit: EmitFn = noop
): Promise<PipelineOutput> {
  const tools = DOMAIN_TOOLS.filter((t) => selected(t.check, scope));
  const results = await Promise.all(
    tools.map(async (t) => {
      const start = Date.now();
      emit({ t: "tool", id: t.check, status: "running", at: start });
      const r = await t.run(host);
      const end = Date.now();
      emit({ t: "tool", id: t.check, status: "done", at: end, ms: end - start, hits: r.findings.length });
      emit({
        t: "log",
        at: end,
        source: t.check,
        message: `${checkName(t.check)}: ${r.findings.length} ${r.findings.length === 1 ? "hit" : "hits"}`,
      });
      return r;
    })
  );
  const findings = results.flatMap((r) => r.findings);
  const checks = results.flatMap((r) => r.checks);
  return {
    mode: "domain",
    target: host,
    ref: new Date().toISOString(),
    findings,
    checks,
    cleanup: async () => {},
  };
}
