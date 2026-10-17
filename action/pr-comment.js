#!/usr/bin/env node
/**
 * Posts (or updates) one Scanner-X summary comment on a pull request: the findings this PR
 * introduces, what wasn't scanned, and a link to the full report. Plain Node 20+, no
 * dependencies. Never fails the job: a fork PR's read-only token just skips the comment.
 *
 * Env: GITHUB_TOKEN, GITHUB_API_URL, GITHUB_SERVER_URL, GITHUB_REPOSITORY, PR_NUMBER,
 *      HEAD_SHA, REPORT_JSON, REPORT_URL (optional), RUN_URL
 */
const fs = require("fs");

const MARKER = "<!-- scanner-x-pr-comment -->";
const MAX_ROWS = 25;
const ORDER = ["critical", "high", "medium", "low"];

const env = (k) => (process.env[k] || "").trim();
const cell = (s) => String(s ?? "").replace(/\r?\n/g, " ").replace(/\|/g, "\\|").replace(/</g, "&lt;").slice(0, 160);

function body(report) {
  const server = env("GITHUB_SERVER_URL") || "https://github.com";
  const repo = env("GITHUB_REPOSITORY");
  const sha = env("HEAD_SHA");
  const findings = report.categories
    .flatMap((c) => c.findings)
    .map((f) => ({ ...f, sev: (f.triage && f.triage.adjusted_severity) || f.severity }))
    .sort((a, b) => ORDER.indexOf(a.sev) - ORDER.indexOf(b.sev));
  const s = report.stats.bySeverity;
  const p = report.policy;
  const lines = [MARKER];

  lines.push(
    `### Scanner-X: ${p.passed ? "passed" : "failed"}`,
    "",
    p.passed
      ? `Nothing at or above **${p.failOn}**.`
      : `**${[p.reason, p.countAtOrAbove ? `${p.countAtOrAbove} at or above ${p.failOn}` : ""].filter(Boolean).join(" · ")}**`,
    ""
  );

  const scope = report.diff
    ? `in the ${report.diff.changedFiles} ${report.diff.changedFiles === 1 ? "file" : "files"} this PR changes`
    : "in the repository";
  lines.push(
    findings.length
      ? `**${findings.length} ${findings.length === 1 ? "finding" : "findings"} ${scope}** (critical ${s.critical} · high ${s.high} · medium ${s.medium} · low ${s.low})`
      : `**No findings ${scope}.**`
  );

  if (findings.length) {
    lines.push("", "| Severity | Finding | Location |", "| --- | --- | --- |");
    for (const f of findings.slice(0, MAX_ROWS)) {
      const file = f.location && f.location.file;
      const line = f.location && f.location.line_start;
      const where = file
        ? `[\`${cell(file)}${line ? `:${line}` : ""}\`](${server}/${repo}/blob/${sha}/${file.split("/").map(encodeURIComponent).join("/")}${line ? `#L${line}` : ""})`
        : cell(f.location && f.location.url);
      const why = f.triage && f.triage.verdict === "true_positive" && f.triage.explanation ? `<br><sub>${cell(f.triage.explanation)}</sub>` : "";
      lines.push(`| **${f.sev}** | ${cell(f.title)}${why} | ${where} |`);
    }
    if (findings.length > MAX_ROWS) lines.push("", `…and ${findings.length - MAX_ROWS} more (see the run summary).`);
  }

  if (report.warning) lines.push("", `> [!WARNING]`, `> ${cell(report.warning)}`);
  for (const n of report.notes || []) lines.push("", `> ${cell(n)}`);

  const links = [];
  if (env("REPORT_URL")) links.push(`[Full report for the default branch](${env("REPORT_URL")})`);
  if (env("RUN_URL")) links.push(`[Run details](${env("RUN_URL")})`);
  links.push("Findings are also on the changed lines under *Files changed*.");
  lines.push("", `<sub>${links.join(" · ")}</sub>`);
  if (report.diff) {
    lines.push("", `<sub>Only problems this PR introduces are listed; issues already on \`${cell(report.diff.baseRef).slice(0, 12)}\` are in the full report.</sub>`);
  }
  return lines.join("\n");
}

async function gh(method, path, payload) {
  const res = await fetch(`${env("GITHUB_API_URL") || "https://api.github.com"}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${env("GITHUB_TOKEN")}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(payload ? { "Content-Type": "application/json" } : {}),
    },
    body: payload ? JSON.stringify(payload) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status}`);
  return res.status === 204 ? null : res.json();
}

async function main() {
  const pr = env("PR_NUMBER");
  if (!pr || !env("GITHUB_TOKEN")) return console.log("Scanner-X: not a pull request; no comment.");
  const report = JSON.parse(fs.readFileSync(env("REPORT_JSON") || "scanner-x.json", "utf8"));
  const text = body(report);
  const repo = env("GITHUB_REPOSITORY");
  let existing = null;
  for (let page = 1; page <= 10 && !existing; page++) {
    const comments = await gh("GET", `/repos/${repo}/issues/${pr}/comments?per_page=100&page=${page}`);
    existing = comments.find((c) => typeof c.body === "string" && c.body.startsWith(MARKER)) || null;
    if (comments.length < 100) break;
  }
  if (existing) await gh("PATCH", `/repos/${repo}/issues/comments/${existing.id}`, { body: text });
  else await gh("POST", `/repos/${repo}/issues/${pr}/comments`, { body: text });
  console.log(`Scanner-X: ${existing ? "updated" : "posted"} the PR comment.`);
}

if (require.main === module) {
  main().catch((err) => {
    // Fork PRs get a read-only token; the check and annotations still work without a comment.
    console.log(`::warning title=Scanner-X::Couldn't post the PR comment (${err.message}). Give the job "pull-requests: write" permission.`);
  });
}

module.exports = { body, MARKER };
