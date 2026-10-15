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
import { ToolRun } from "../tools/types";
import { gitEnv, redactSecrets } from "../tools/gitAuth";
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
  run: (
    repoDir: string,
    opts: { fullHistory: boolean; logOpts?: string; env?: Record<string, string> }
  ) => Promise<ToolRun>;
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
  /** True when the target wasn't actually scanned; fails the policy. */
  incomplete?: boolean;
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
async function runTracked(
  check: string,
  fn: () => Promise<ToolRun>,
  emit: EmitFn
): Promise<ToolRun> {
  const start = Date.now();
  emit({ t: "tool", id: check, status: "running", at: start });
  const run = await fn();
  const end = Date.now();
  const hits = run.findings.length;
  if (run.ran) {
    emit({ t: "tool", id: check, status: "done", at: end, ms: end - start, hits });
  } else {
    emit({ t: "tool", id: check, status: "error", at: end, ms: end - start, hits, message: run.error ?? "did not run" });
  }
  emit({
    t: "log",
    at: end,
    source: check,
    message: run.ran
      ? `${checkName(check)}: ${hits} ${hits === 1 ? "hit" : "hits"}`
      : `${checkName(check)}: NOT SCANNED (${run.error ?? "did not run"})`,
  });
  return run;
}

export interface RepoScanOptions {
  fullHistory?: boolean;
  baseRef?: string;
  headRef?: string;
}

// https only, no redirects (a clone can't be bounced to an internal host), and no credential
// helpers: private repos authenticate only with tokens configured in gitAuth.ts, never with
// whatever login the server's user has saved (e.g. the macOS Keychain).
const GIT_SAFE = [
  "-c", "protocol.allow=never",
  "-c", "protocol.https.allow=always",
  "-c", "http.followRedirects=false",
  "-c", "credential.helper=",
];

function gitError(res: { spawnError?: string; stderr: string; code: number | null }, what: string): string {
  return redactSecrets(res.spawnError || res.stderr.trim() || `${what} exited with code ${res.code}`);
}

/**
 * Fetch a ref from origin and return its full SHA. Servers only accept full SHAs, so an
 * abbreviated one is resolved against the already-cloned history instead.
 */
async function resolveRef(dir: string, ref: string, env: Record<string, string>): Promise<string | null> {
  const fetch = await runCommand(
    "git",
    [...GIT_SAFE, "fetch", "--no-tags", "origin", "--", ref],
    { cwd: dir, timeoutMs: 300000, env }
  );
  if (!fetch.spawnError && fetch.code === 0) {
    const head = await runCommand("git", ["rev-parse", "FETCH_HEAD"], { cwd: dir });
    if (head.code === 0) return head.stdout.trim();
  }
  if (/^[0-9a-f]{7,39}$/i.test(ref)) {
    const local = await runCommand(
      "git",
      ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`],
      { cwd: dir }
    );
    if (local.code === 0) return local.stdout.trim();
  }
  return null;
}

const REF_HINT =
  "use a branch name, a PR/MR ref (refs/pull/N/head on GitHub, refs/merge-requests/N/head on GitLab), or the full 40-character SHA";

async function cloneRepo(
  repoUrl: string,
  opts: { fullHistory: boolean; baseRef?: string; headRef?: string }
): Promise<{ dir: string; ref: string; baseSha?: string; changed?: Set<string>; error?: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-"));
  const env = gitEnv(repoUrl);
  const historyArgs = opts.baseRef
    ? ["--filter=blob:none"]
    : opts.fullHistory
      ? []
      : ["--depth", "1"];
  // Persist the same restrictions for lazy blob fetches made later by checkout and gitleaks.
  const persistArgs = GIT_SAFE.map((arg) => (arg === "-c" ? "--config" : arg));
  const checkoutArgs = opts.headRef ? ["--no-checkout"] : [];
  const clone = await runCommand(
    "git",
    [...GIT_SAFE, "clone", "--no-tags", ...persistArgs, ...historyArgs, ...checkoutArgs, "--", repoUrl, dir],
    { timeoutMs: opts.fullHistory || opts.baseRef ? 600000 : 120000, env }
  );
  let ref = new Date().toISOString();
  if (clone.spawnError || clone.code !== 0) {
    return { dir, ref, error: gitError(clone, "git clone") };
  }
  // Fetch-then-checkout accepts branches, SHAs and refs/pull/N/head (fork PRs), unlike clone --branch.
  if (opts.headRef) {
    const headSha = await resolveRef(dir, opts.headRef, env);
    if (!headSha) {
      return { dir, ref, error: `could not find head ref ${opts.headRef}; ${REF_HINT}` };
    }
    const checkout = await runCommand(
      "git",
      [...GIT_SAFE, "checkout", "--detach", headSha],
      { cwd: dir, timeoutMs: 300000, env }
    );
    if (checkout.spawnError || checkout.code !== 0) {
      return { dir, ref, error: `could not check out ${opts.headRef}: ${gitError(checkout, "git checkout")}` };
    }
  }
  const rev = await runCommand("git", ["rev-parse", "HEAD"], { cwd: dir });
  if (rev.code === 0) ref = rev.stdout.trim();
  if (!opts.baseRef) return { dir, ref };

  const baseSha = await resolveRef(dir, opts.baseRef, env);
  if (!baseSha) {
    return { dir, ref, error: `could not find base ref ${opts.baseRef}; ${REF_HINT}` };
  }
  const diff = await runCommand(
    "git",
    ["diff", "--name-only", "-z", `${baseSha}...HEAD`],
    { cwd: dir, timeoutMs: 120000, env }
  );
  if (diff.code !== 0) {
    return { dir, ref, error: `could not diff against ${opts.baseRef}: ${gitError(diff, "git diff")}` };
  }
  const changed = new Set(diff.stdout.split("\0").filter(Boolean));
  return { dir, ref: `${baseSha}...${ref}`, baseSha, changed };
}

const DEPENDENCY_FILES = new Set([
  "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
]);

function inChangedFiles(finding: Finding, dirs: string[], changed: Set<string>): boolean {
  // Gitleaks already scanned only the PR's commit range.
  if (finding.skill.startsWith("gitleaks-")) return true;
  const file = finding.location.file;
  if (!file) return false;
  // Keep a manifest's findings when a dependency file changed in its directory or a workspace below it.
  if (finding.skill.startsWith("npm-audit")) {
    const manifestDir = path.posix.dirname(file);
    return [...changed].some(
      (f) =>
        DEPENDENCY_FILES.has(path.posix.basename(f)) &&
        (manifestDir === "." || f.startsWith(`${manifestDir}/`))
    );
  }
  return dirs.some((dir) => {
    const rel = path.relative(dir, path.resolve(dir, file)).split(path.sep).join("/");
    return changed.has(rel);
  });
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

export async function runRepoPipeline(
  repoUrl: string,
  scope: Scope,
  opts: RepoScanOptions = {},
  emit: EmitFn = noop
): Promise<PipelineOutput> {
  let dir: string;
  let ref = new Date().toISOString();
  let warning: string | undefined;
  let baseSha: string | undefined;
  let changed: Set<string> | undefined;
  const scanHistory = opts.fullHistory === true && selected("secrets", scope);
  try {
    const cloned = await cloneRepo(repoUrl, {
      fullHistory: scanHistory,
      baseRef: opts.baseRef,
      headRef: opts.headRef,
    });
    dir = cloned.dir;
    ref = cloned.ref;
    baseSha = cloned.baseSha;
    changed = cloned.changed;
    if (cloned.error) {
      warning = `Repository clone failed (${cloned.error}). No repository code was scanned.`;
    } else if (!(await hasScannableFiles(dir))) {
      warning = "Repository has no scannable code or dependency manifests. No repository code was scanned.";
    }
  } catch (err) {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "scanner-x-"));
    warning = `Repository clone failed (${redactSecrets((err as Error).message)}). No repository code was scanned.`;
  }

  if (warning) {
    emit({ t: "log", at: Date.now(), source: "clone", message: warning });
    return {
      mode: "repo",
      target: repoUrl,
      ref,
      findings: [],
      warning,
      incomplete: true,
      checks: [],
      repoDir: dir,
      cleanup: async () => {
        await fs.rm(dir, { recursive: true, force: true });
      },
    };
  }

  if (changed) {
    emit({
      t: "log",
      at: Date.now(),
      source: "clone",
      message: `Diff mode: ${changed.size} changed ${changed.size === 1 ? "file" : "files"} vs ${opts.baseRef}`,
    });
  }

  const toolOpts = {
    fullHistory: scanHistory,
    logOpts: baseSha ? `${baseSha}..HEAD` : undefined,
    // Partial (blob-less) clones fetch blobs lazily while gitleaks reads history; those
    // fetches need the same auth header and no-prompt settings as the clone.
    env: gitEnv(repoUrl),
  };
  const tools = REPO_TOOLS.filter((t) => selected(t.check, scope));
  const runs = await Promise.all(
    tools.map((t) => runTracked(t.check, () => t.run(dir, toolOpts), emit))
  );
  let findings = runs.flatMap((r) => r.findings);
  if (changed) {
    const dirs = [dir, await fs.realpath(dir)];
    findings = findings.filter((f) => inChangedFiles(f, dirs, changed!));
  }
  const skipped = tools
    .map((t, i) => ({ check: t.check, run: runs[i] }))
    .filter(({ run }) => !run.ran);
  const skippedWarning = skipped.length
    ? `Not scanned: ${skipped
        .map(({ check, run }) => `${checkName(check)} (${run.error ?? "did not run"})`)
        .join(", ")}.`
    : undefined;

  return {
    mode: "repo",
    target: repoUrl,
    ref,
    findings,
    ...(skippedWarning ? { warning: skippedWarning, incomplete: true } : {}),
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
