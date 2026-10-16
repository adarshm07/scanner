#!/usr/bin/env node
/**
 * Scanner-X CLI: scan a repository that is already checked out (local dev, CI, or a coding
 * agent) without the web server. Writes SARIF and/or JSON and exits non-zero when the
 * policy fails, so it can gate a pull request.
 *
 *   node dist/cli.js --path . --base origin/main --fail-on high --sarif scanner-x.sarif
 */
import { promises as fs } from "fs";
import path from "path";
import { runLocalRepoPipeline, Scope } from "./orchestrator/runPipeline";
import { generateReport } from "./orchestrator/report";
import { toSarif } from "./orchestrator/sarif";
import { CHECKS } from "./orchestrator/checks";
import { resolveProvider, listProviders } from "./llm";
import { Report, Severity, SEVERITY_RANK } from "./schema/finding";
import { ScanEvent } from "./orchestrator/events";
import { applyTriage } from "./orchestrator/applyTriage";

const USAGE = `Usage: scanner-x [options]

Scans a local git checkout with gitleaks, semgrep and npm audit.

Options:
  --path <dir>          Repository to scan (default: current directory)
  --base <ref>          Diff mode: only report findings in files changed since <ref>
                        (branch, tag or SHA present in the local history)
  --checks <list>       Comma-separated: ${CHECKS.filter((c) => c.mode === "repo").map((c) => c.id).join(", ")} (default: all)
  --fail-on <severity>  critical | high | medium | low (default: high)
  --full-history        Scan every commit for secrets, not just the current files
  --sarif <file>        Write SARIF 2.1.0 (for GitHub code scanning)
  --json <file>         Write the full report as JSON
  --triage <provider>   Explain findings with an LLM: gemini | claude | openai
                        (default: off; sends code snippets to the provider)
  --target <name>       Name to show in the report (default: the path)
  --quiet               Only print the final summary
  -h, --help            Show this help

Exit codes: 0 policy passed, 1 policy failed or scan incomplete, 2 usage error.

Merge verdicts from your own reviewer (e.g. a coding agent) into a saved report:
  scanner-x apply-triage --report <scan.json> --triage <verdicts.json>
                         [--json <out.json>] [--sarif <out.sarif>] [--path <repo>] [--fail-on <sev>]
  verdicts.json: [{ "finding_id", "verdict": "true_positive"|"false_positive"|"needs_review",
                    "adjusted_severity"?, "explanation", "suggested_fix"? }, ...]
  --json defaults to overwriting --report. Same exit codes.`;

interface Args {
  path: string;
  base?: string;
  checks: Scope;
  failOn: Severity;
  fullHistory: boolean;
  sarif?: string;
  json?: string;
  triage?: string;
  target?: string;
  quiet: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: string[]): Args | "help" {
  const args: Args = { path: process.cwd(), checks: "all", failOn: "high", fullHistory: false, quiet: false };
  const repoChecks = new Set(CHECKS.filter((c) => c.mode === "repo").map((c) => c.id));
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new UsageError(`${flag} needs a value`);
      return v;
    };
    switch (flag) {
      case "-h":
      case "--help":
        return "help";
      case "--path": args.path = path.resolve(value()); break;
      case "--base": args.base = value(); break;
      case "--checks": {
        const v = value();
        if (v === "all") { args.checks = "all"; break; }
        const list = v.split(",").map((s) => s.trim()).filter(Boolean);
        const bad = list.filter((c) => !repoChecks.has(c));
        if (bad.length || list.length === 0) throw new UsageError(`unknown check(s): ${bad.join(", ") || v}`);
        args.checks = list;
        break;
      }
      case "--fail-on": {
        const v = value();
        if (!(v in SEVERITY_RANK)) throw new UsageError(`--fail-on must be critical, high, medium or low`);
        args.failOn = v as Severity;
        break;
      }
      case "--full-history": args.fullHistory = true; break;
      case "--sarif": args.sarif = path.resolve(value()); break;
      case "--json": args.json = path.resolve(value()); break;
      case "--triage": args.triage = value(); break;
      case "--target": args.target = value(); break;
      case "--quiet": args.quiet = true; break;
      default:
        throw new UsageError(`unknown option: ${flag}`);
    }
  }
  if (args.base && (args.base.startsWith("-") || /\s/.test(args.base))) {
    throw new UsageError("--base must be a branch, tag or commit SHA");
  }
  return args;
}

function logEvent(e: ScanEvent): void {
  if (e.t === "log") process.stderr.write(`  ${e.message}\n`);
  else if (e.t === "tool" && e.status === "error") process.stderr.write(`  ! ${e.id}: ${e.message}\n`);
}

function summary(report: Report): string {
  const s = report.stats.bySeverity;
  const lines = [
    `Scanner-X: ${report.target}`,
    report.diff
      ? `Diff: ${report.diff.changedFiles} ${report.diff.changedFiles === 1 ? "file" : "files"} changed vs ${report.diff.baseRef}`
      : `Ref: ${report.ref.slice(0, 12)}`,
    `Findings: ${report.stats.totalAfterFilter} (critical ${s.critical}, high ${s.high}, medium ${s.medium}, low ${s.low})`,
  ];
  if (report.warning) lines.push(`Warning: ${report.warning}`);
  for (const n of report.notes ?? []) lines.push(`Note: ${n}`);
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const all = report.categories
    .flatMap((c) => c.findings)
    .sort((a, b) => order.indexOf(a.triage?.adjusted_severity ?? a.severity) - order.indexOf(b.triage?.adjusted_severity ?? b.severity));
  for (const f of all.slice(0, 25)) {
    const sev = f.triage?.adjusted_severity ?? f.severity;
    const loc = f.location.file ? `${f.location.file}${f.location.line_start ? `:${f.location.line_start}` : ""}` : f.location.url ?? "";
    const verdict = f.triage && f.triage.verdict !== "needs_review" ? ` [${f.triage.verdict.replace("_", " ")}]` : "";
    lines.push(`  [${sev}] ${f.title} (${loc})${verdict}`);
  }
  if (all.length > 25) lines.push(`  … ${all.length - 25} more (see --json or --sarif output)`);
  lines.push(
    report.policy.passed
      ? `Policy: PASSED (nothing at or above ${report.policy.failOn})`
      : `Policy: FAILED (${[report.policy.reason, report.policy.countAtOrAbove ? `${report.policy.countAtOrAbove} at or above ${report.policy.failOn}` : ""].filter(Boolean).join("; ")})`
  );
  return lines.join("\n");
}

async function applyTriageCommand(argv: string[]): Promise<number> {
  const opts: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "-h" || flag === "--help") {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    }
    if (!["--report", "--triage", "--json", "--sarif", "--path", "--fail-on"].includes(flag)) {
      process.stderr.write(`scanner-x apply-triage: unknown option: ${flag}\n`);
      return 2;
    }
    const v = argv[++i];
    if (v === undefined || v.startsWith("--")) {
      process.stderr.write(`scanner-x apply-triage: ${flag} needs a value\n`);
      return 2;
    }
    opts[flag.slice(2)] = v;
  }
  if (!opts.report || !opts.triage) {
    process.stderr.write("scanner-x apply-triage: --report and --triage are required\n");
    return 2;
  }
  if (opts["fail-on"] && !(opts["fail-on"] in SEVERITY_RANK)) {
    process.stderr.write("scanner-x apply-triage: --fail-on must be critical, high, medium or low\n");
    return 2;
  }
  let report: Report;
  let entries: unknown;
  try {
    report = JSON.parse(await fs.readFile(path.resolve(opts.report), "utf8")) as Report;
    entries = JSON.parse(await fs.readFile(path.resolve(opts.triage), "utf8"));
  } catch (err) {
    process.stderr.write(`scanner-x apply-triage: could not read input (${(err as Error).message})\n`);
    return 2;
  }
  let result;
  try {
    result = applyTriage(report, entries, { failOn: opts["fail-on"] as Severity | undefined });
  } catch (err) {
    process.stderr.write(`scanner-x apply-triage: ${(err as Error).message}\n`);
    return 2;
  }
  for (const id of result.unknownIds) process.stderr.write(`  ! unknown finding_id ${id} (ignored)\n`);
  for (const msg of result.invalid) process.stderr.write(`  ! ${msg} (ignored)\n`);
  process.stderr.write(
    `Applied ${result.applied} verdict(s); ${result.removedAsFalsePositive} false positive(s) removed.\n`
  );

  const out = path.resolve(opts.json ?? opts.report);
  await fs.writeFile(out, JSON.stringify(result.report, null, 2));
  if (opts.sarif) {
    const root = path.resolve(opts.path ?? process.cwd());
    const sarifPath = path.resolve(opts.sarif);
    await fs.mkdir(path.dirname(sarifPath), { recursive: true });
    await fs.writeFile(sarifPath, JSON.stringify(toSarif(result.report, [root, await fs.realpath(root)]), null, 2));
  }
  process.stdout.write(`${summary(result.report)}\n`);
  return result.report.policy.passed ? 0 : 1;
}

async function main(): Promise<number> {
  if (process.argv[2] === "apply-triage") return applyTriageCommand(process.argv.slice(3));
  let args: Args | "help";
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`scanner-x: ${(err as Error).message}\n\n${USAGE}\n`);
    return 2;
  }
  if (args === "help") {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  try {
    const stat = await fs.stat(args.path);
    if (!stat.isDirectory()) throw new Error();
  } catch {
    process.stderr.write(`scanner-x: --path ${args.path} is not a directory\n`);
    return 2;
  }

  let llm = null;
  if (args.triage) {
    llm = resolveProvider(args.triage);
    if (!llm || llm.id !== args.triage) {
      const known = listProviders().map((p) => `${p.id}${p.available ? "" : " (not configured)"}`).join(", ");
      process.stderr.write(`scanner-x: triage provider "${args.triage}" is not available. Providers: ${known}\n`);
      return 2;
    }
  }

  const emit = args.quiet ? () => {} : logEvent;
  if (!args.quiet) process.stderr.write(`Scanning ${args.path}${args.base ? ` (changes since ${args.base})` : ""}…\n`);
  const pipeline = await runLocalRepoPipeline(
    args.path,
    args.checks,
    { baseRef: args.base, fullHistory: args.fullHistory, target: args.target },
    emit
  );
  let report: Report;
  try {
    report = await generateReport(pipeline, llm, args.failOn, emit);
  } finally {
    await pipeline.cleanup();
  }

  const roots = [args.path, await fs.realpath(args.path)];
  if (args.sarif) {
    await fs.mkdir(path.dirname(args.sarif), { recursive: true });
    await fs.writeFile(args.sarif, JSON.stringify(toSarif(report, roots), null, 2));
  }
  if (args.json) {
    await fs.mkdir(path.dirname(args.json), { recursive: true });
    await fs.writeFile(args.json, JSON.stringify(report, null, 2));
  }
  process.stdout.write(`${summary(report)}\n`);
  return report.policy.passed ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`scanner-x: ${(err as Error).stack ?? err}\n`);
    process.exit(2);
  }
);
