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
  run: (repoDir: string, fullHistory?: boolean) => Promise<Finding[]>;
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
  warning?: string;
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

async function cloneRepo(
  repoUrl: string,
  fullHistory: boolean
): Promise<{ dir: string; ref: string; error?: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-"));
  const depthArgs = fullHistory ? [] : ["--depth", "1"];
  const clone = await runCommand(
    "git",
    ["clone", ...depthArgs, repoUrl, dir],
    { timeoutMs: fullHistory ? 600000 : 120000 }
  );
  let ref = new Date().toISOString();
  if (!clone.spawnError && clone.code === 0) {
    const rev = await runCommand("git", ["rev-parse", "HEAD"], { cwd: dir });
    if (rev.code === 0) ref = rev.stdout.trim();
  }
  return {
    dir,
    ref,
    ...(clone.spawnError || clone.code !== 0
      ? { error: clone.spawnError || clone.stderr.trim() || `git clone exited with code ${clone.code}` }
      : {}),
  };
}

async function hasScannableFiles(dir: string): Promise<boolean> {
  const codeExtensions = new Set([
    ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".scala",
    ".sh", ".sql", ".swift", ".ts", ".tsx", ".vue", ".xml",
  ]);
  const manifests = new Set([
    "cargo.toml", "composer.json", "dockerfile", "gemfile", "go.mod",
    "package.json", "pipfile", "pyproject.toml", "requirements.txt",
  ]);
  const visit = async (current: string): Promise<boolean> => {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "vendor") continue;
      if (entry.isDirectory()) {
        if (await visit(path.join(current, entry.name))) return true;
      } else if (
        codeExtensions.has(path.extname(entry.name).toLowerCase()) ||
        manifests.has(entry.name.toLowerCase())
      ) {
        return true;
      }
    }
    return false;
  };
  return visit(dir);
}

function demoFindings(): Finding[] {
  const examples: Pick<Finding, "skill" | "rule_id" | "severity" | "title" | "location" | "tool_message" | "metadata">[] = [
    {
      skill: "demo-hardcoded-secret",
      rule_id: "demo-hardcoded-secret",
      severity: "high",
      title: "[Demo] Hardcoded credential example",
      location: { file: "src/config.ts", line_start: 12, line_end: 12 },
      tool_message: "DEMO ONLY: Illustrative hardcoded credential finding; this was not detected in the target repository.",
      metadata: { demo: true, cwe: "CWE-798" },
    },
    {
      skill: "demo-unsafe-input",
      rule_id: "demo-unsafe-input",
      severity: "medium",
      title: "[Demo] Unvalidated input reaches a sensitive operation",
      location: { file: "src/routes.ts", line_start: 34, line_end: 34 },
      tool_message: "DEMO ONLY: Illustrative input-validation finding; this was not detected in the target repository.",
      metadata: { demo: true, cwe: "CWE-20" },
    },
  ];
  return examples.map((finding) => ({
    ...finding,
    category: "backend",
    finding_id: `${finding.rule_id}-demo`,
    confidence: "low",
    raw_snippet: null,
  }));
}

export async function runRepoPipeline(
  repoUrl: string,
  scope: Scope,
  fullHistory = false,
  emit: EmitFn = noop
): Promise<PipelineOutput> {
  let dir: string;
  let ref = new Date().toISOString();
  let warning: string | undefined;
  const scanHistory = fullHistory && selected("secrets", scope);
  try {
    const cloned = await cloneRepo(repoUrl, scanHistory);
    dir = cloned.dir;
    ref = cloned.ref;
    if (cloned.error) {
      warning = `Repository clone failed (${cloned.error}). No repository code was scanned; showing demo findings.`;
    } else if (!(await hasScannableFiles(dir))) {
      warning = "Repository has no scannable code or dependency manifests. No repository code was scanned; showing demo findings.";
    }
  } catch (err) {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-"));
    warning = `Repository clone failed (${(err as Error).message}). No repository code was scanned; showing demo findings.`;
  }

  if (warning) {
    emit({ t: "error", message: warning });
    return {
      mode: "repo",
      target: repoUrl,
      ref,
      findings: demoFindings(),
      warning,
      checks: [],
      repoDir: dir,
      cleanup: async () => {
        await fs.rm(dir, { recursive: true, force: true });
      },
    };
  }

  const tools = REPO_TOOLS.filter((t) => selected(t.check, scope));
  const results = await Promise.all(
    tools.map((t) => runTracked(t.check, () => t.run(dir, scanHistory), emit))
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
