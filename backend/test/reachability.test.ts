import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { buildLockGraph, directAncestors, enrichWithUsage, findUsage } from "../src/tools/depUsage";
import { enforceReachability, dependencyBucket, dependencyNote } from "../src/orchestrator/reachability";
import { applyTriage } from "../src/orchestrator/applyTriage";
import { renderHtml } from "../src/orchestrator/html";
import { Finding, Report, ReportFinding, Severity, TriageResult } from "../src/schema/finding";

function dep(pkg: string, severity: Severity, meta: Record<string, unknown> = {}): Finding {
  return {
    skill: `npm-audit-${pkg}`,
    category: "dependencies",
    finding_id: `id-${pkg}`,
    rule_id: `https://github.com/advisories/GHSA-${pkg}`,
    severity,
    confidence: "high",
    title: `${pkg}: something bad`,
    location: { file: "package.json" },
    raw_snippet: null,
    tool_message: `${pkg} is vulnerable.`,
    metadata: { package: pkg, ...meta },
  };
}

function verdict(f: Finding, over: Partial<TriageResult>): TriageResult {
  return {
    finding_id: f.finding_id,
    verdict: "true_positive",
    adjusted_severity: f.severity,
    explanation: "because",
    suggested_fix: "upgrade",
    ...over,
  };
}

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sx-usage-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

test("finds require, import, subpath and dynamic import sites", () => {
  const src = (rel: string, text: string) => ({ rel, lines: text.split("\n"), python: false });
  const sources = [
    src("a.js", "const m = require('marked');"),
    src("b.ts", 'import { x } from "lodash/merge";'),
    src("c.mjs", "const y = await import(`qs`);"),
    src("d.js", "const markedown = require('markedown');"),
  ];
  assert.equal(findUsage(["marked"], sources, [], false).sites.length, 1);
  assert.equal(findUsage(["lodash"], sources, [], false).status, "imported");
  assert.equal(findUsage(["qs"], sources, [], false).status, "imported");
  // A longer name that merely starts with the package name is not a match.
  assert.equal(findUsage(["markdown"], sources, [], false).status, "not_found");
});

test("a transitive package counts as imported through the direct dependency that pulls it in", () => {
  const sources = [{ rel: "server.js", lines: ["const express = require('express');"], python: false }];
  const u = findUsage(["qs", "express"], sources, [], false);
  assert.equal(u.status, "imported");
  assert.equal(u.sites[0].pkg, "express");
});

test("string references and package.json scripts count as referenced, not imported", () => {
  const sources = [{ rel: "server.js", lines: ['app.set("view engine", "ejs");'], python: false }];
  assert.equal(findUsage(["ejs"], sources, [], false).status, "referenced");
  const scripts = [{ file: "package.json", scripts: { start: "forever start server.js" } }];
  const u = findUsage(["forever"], [], scripts, false);
  assert.equal(u.status, "referenced");
  assert.equal(u.sites[0].kind, "script");
});

test("python imports are found with dashes normalised", () => {
  const sources = [{ rel: "app.py", lines: ["from python_jose import jwt", "import requests, yaml"], python: true }];
  assert.equal(findUsage(["python-jose"], sources, [], true).status, "imported");
  assert.equal(findUsage(["yaml"], sources, [], true).status, "imported");
  assert.equal(findUsage(["flask"], sources, [], true).status, "not_found");
});

test("the lockfile graph finds the direct dependency behind a transitive package", () => {
  const lock = {
    packages: {
      "": { dependencies: { express: "^4" } },
      "node_modules/express": { dependencies: { "proxy-addr": "~2", "body-parser": "1" } },
      "node_modules/body-parser": { dependencies: { qs: "6" } },
      "node_modules/proxy-addr": {},
      "node_modules/qs": {},
      "node_modules/nodemon": { dependencies: { chokidar: "3" } },
    },
  };
  const g = buildLockGraph(lock, { dependencies: { express: "^4" }, devDependencies: { nodemon: "2" } });
  assert.deepEqual(directAncestors(g, "proxy-addr"), ["express"]);
  assert.deepEqual(directAncestors(g, "qs"), ["express"]);
  assert.deepEqual(directAncestors(g, "chokidar"), ["nodemon"]);
  assert.deepEqual(directAncestors(g, "express"), ["express"]);
  // lockfileVersion 1
  const v1 = buildLockGraph({ dependencies: { express: { requires: { qs: "6" } }, qs: {} } }, { dependencies: { express: "4" } });
  assert.deepEqual(directAncestors(v1, "qs"), ["express"]);
});

test("short package names don't match ordinary strings", () => {
  const sources = [{ rel: "Gruntfile.js", lines: ["opts.split('i');"], python: false }];
  assert.equal(findUsage(["i"], sources, [], false).status, "not_found");
});

test("a transitive package with no known path is unknown, never lowered", async () => {
  const dir = repo({ "server.js": "require('express');\n", "package.json": "{}" });
  const f = dep("orphan", "high");
  await enrichWithUsage(dir, [f]);
  assert.equal((f.metadata.usage as { status: string }).status, "unknown");
  assert.equal(f.severity, "high");
});

test("a transitive package of an imported framework is imported, via the lockfile", async () => {
  const dir = repo({
    "server.js": "const express = require('express');\n",
    "package.json": JSON.stringify({ dependencies: { express: "4" } }),
    "package-lock.json": JSON.stringify({ packages: { "": {}, "node_modules/express": { dependencies: { "proxy-addr": "2" } }, "node_modules/proxy-addr": {} } }),
  });
  const f = dep("proxy-addr", "high");
  await enrichWithUsage(dir, [f]);
  const u = f.metadata.usage as { status: string; sites: { pkg: string }[] };
  assert.equal(u.status, "imported");
  assert.equal(u.sites[0].pkg, "express");
  assert.equal(f.severity, "high");
});

test("enrichWithUsage lowers never-loaded production packages one level, but not KEV or dev-only", async () => {
  const dir = repo({
    "server.js": "const express = require('express');\n",
    "test/helper.js": "const unused = require('unused-in-app');\n",
  });
  const findings = [
    dep("express", "high"),
    dep("unused-in-app", "high", { direct: true }),
    dep("exploited", "critical", { kev: true }),
    dep("devtool", "low", { devOnly: true }),
  ];
  const res = await enrichWithUsage(dir, findings);
  assert.equal(res.lowered, 1);
  assert.equal(findings[0].severity, "high");
  assert.equal((findings[0].metadata.usage as { status: string }).status, "imported");
  // Only imported from a test file, which doesn't ship.
  assert.equal(findings[1].severity, "medium");
  assert.match(findings[1].tool_message, /installed but not loaded/);
  assert.equal(findings[2].severity, "critical");
  assert.equal(findings[3].severity, "low");
});

test("not_reachable drops to low, or medium for KEV; it is never removed", () => {
  const f = dep("marked", "high");
  assert.deepEqual(
    [enforceReachability(f, verdict(f, { reachability: "not_reachable" })).adjusted_severity, enforceReachability(f, verdict(f, { reachability: "not_reachable" })).verdict],
    ["low", "true_positive"]
  );
  const kev = dep("bad", "critical", { kev: true });
  assert.equal(enforceReachability(kev, verdict(kev, { reachability: "not_reachable", adjusted_severity: "low" })).adjusted_severity, "medium");
  // A false-positive verdict on a dependency becomes not_reachable, not a deletion.
  const fp = enforceReachability(f, verdict(f, { verdict: "false_positive" }));
  assert.equal(fp.verdict, "true_positive");
  assert.equal(fp.reachability, "not_reachable");
});

test("reachable keeps at least the scanner severity; unknown can drop one level at most", () => {
  const f = dep("express", "high");
  assert.equal(enforceReachability(f, verdict(f, { reachability: "reachable", adjusted_severity: "low" })).adjusted_severity, "high");
  assert.equal(enforceReachability(f, verdict(f, { reachability: "reachable", adjusted_severity: "critical" })).adjusted_severity, "critical");
  assert.equal(enforceReachability(f, verdict(f, { reachability: "unknown", adjusted_severity: "low" })).adjusted_severity, "medium");
  // Missing reachability is treated as unknown.
  assert.equal(enforceReachability(f, verdict(f, { adjusted_severity: "low" })).reachability, "unknown");
});

test("code findings are untouched by the dependency rules", () => {
  const code: Finding = { ...dep("x", "high"), skill: "semgrep-rule", category: "backend" };
  const r = verdict(code, { verdict: "false_positive", adjusted_severity: "low" });
  assert.deepEqual(enforceReachability(code, r), r);
});

function report(findings: ReportFinding[]): Report {
  return {
    reportId: "r",
    mode: "repo",
    target: "o/r",
    ref: "abc",
    createdAt: "2026-10-18T00:00:00.000Z",
    executiveSummary: "",
    categories: [
      { category: "backend", findings: findings.filter((f) => f.category !== "dependencies") },
      { category: "dependencies", findings: findings.filter((f) => f.category === "dependencies") },
    ],
    checks: [],
    stats: { totalRaw: findings.length, totalAfterFilter: findings.length, bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0 } },
    policy: { failOn: "high", passed: false, countAtOrAbove: findings.length },
    ai: { provider: null, triageEnabled: false, llmFallbackUsed: false },
  };
}

test("apply-triage takes reachability from the agent and stops unreachable advisories failing the policy", () => {
  const a = { ...dep("express", "high", { usage: { status: "imported", sites: [], searched: ["express"], totalSites: 1 } }), triage: null };
  const b = { ...dep("marked", "high", { usage: { status: "imported", sites: [], searched: ["marked"], totalSites: 1 } }), triage: null };
  const res = applyTriage(report([a, b]), [
    { finding_id: a.finding_id, verdict: "true_positive", reachability: "reachable", explanation: "body parsing on every request" },
    { finding_id: b.finding_id, verdict: "false_positive", reachability: "not_reachable", explanation: "only used in a build script" },
  ]);
  assert.equal(res.applied, 2);
  assert.equal(res.removedAsFalsePositive, 0);
  assert.equal(res.report.policy.countAtOrAbove, 1);
  const kept = res.report.categories.flatMap((c) => c.findings);
  assert.equal(kept.length, 2);
  assert.equal(dependencyBucket(kept.find((f) => f.finding_id === b.finding_id)!), "not_reachable");
  assert.ok(res.report.notes?.some((n) => n.startsWith("Dependencies: 1 reachable, 1 used but not reachable")));
});

test("apply-triage rejects an invalid reachability value", () => {
  const a = { ...dep("express", "high"), triage: null };
  const res = applyTriage(report([a]), [{ finding_id: a.finding_id, verdict: "true_positive", reachability: "maybe", explanation: "x" }]);
  assert.equal(res.applied, 0);
  assert.match(res.invalid[0], /reachability must be one of/);
});

test("HTML puts code findings first and groups dependencies by reachability", () => {
  const code: ReportFinding = { ...dep("x", "high"), skill: "semgrep-sqli", category: "backend", title: "SQL injection", triage: null };
  const reach: ReportFinding = { ...dep("express", "high"), triage: verdict(dep("express", "high"), { reachability: "reachable" }) };
  const unused: ReportFinding = { ...dep("left-pad", "medium", { usage: { status: "not_found", sites: [], searched: ["left-pad"], totalSites: 0 } }), triage: null };
  const html = renderHtml(report([code, reach, unused]));
  const codeAt = html.indexOf("SQL injection");
  const depsAt = html.indexOf("<h2>Dependencies (2)</h2>");
  assert.ok(codeAt > 0 && depsAt > codeAt);
  assert.ok(html.indexOf("Reachable: the app uses the vulnerable code") < html.indexOf("Installed, but never loaded by the app"));
  assert.equal(dependencyNote([code, reach, unused]), "Dependencies: 1 reachable, 1 never loaded by the app. Only reachable or unconfirmed advisories keep their full severity.");
});

test("built-in AI triage uses the dependency prompt and its reachability call is enforced", async () => {
  const { triageCategory } = await import("../src/orchestrator/triage");
  const seen: { system: string; user: string }[] = [];
  const a = dep("qs", "high", { usage: { status: "imported", sites: [{ pkg: "express", file: "server.js", line: 3, kind: "import" }], searched: ["qs", "express"], totalSites: 1 } });
  const b = dep("underscore", "critical", { direct: true });
  const provider = {
    id: "claude" as const,
    async generate(msg: { system: string; user: string }) {
      seen.push(msg);
      return JSON.stringify({
        results: [
          { finding_id: a.finding_id, reachability: "reachable", verdict: "true_positive", adjusted_severity: "low", explanation: "Express parses every query string with qs (server.js:3).", suggested_fix: "1. npm install express@4.22.1\n2. npm ls qs" },
          { finding_id: b.finding_id, reachability: "not_reachable", verdict: "false_positive", adjusted_severity: "medium", explanation: "The app never calls _.template (config/config.js:1 only merges objects).", suggested_fix: "1. npm install underscore@1.13.8\n2. npm ls underscore" },
        ],
      });
    },
  };
  const out = await triageCategory(provider, "dependencies", "o/r", [a, b]);
  assert.match(seen[0].system, /decide whether THIS app can actually reach the vulnerable code/);
  assert.match(seen[0].user, /"reachability": "reachable"\|"not_reachable"\|"unknown"/);
  // Reachable can't be rated below the scanner's severity.
  assert.equal(out.results.get(a.finding_id)!.adjusted_severity, "high");
  // A dependency is never dropped as a false positive; unreachable goes to low.
  assert.equal(out.results.get(b.finding_id)!.verdict, "true_positive");
  assert.equal(out.results.get(b.finding_id)!.adjusted_severity, "low");
});
