import { test } from "node:test";
import assert from "node:assert/strict";
import { npmAuditAdapter } from "../src/tools/npmAudit";
import { isNonProductionGroup } from "../src/tools/osvScanner";
import { applyExploitIntel } from "../src/tools/exploitIntel";
import { filterFindings, isNonProductionPath } from "../src/orchestrator/filterFindings";
import { Finding } from "../src/schema/finding";

// ------------------------------------------------------------ 1. dev vs production

const AUDIT = {
  vulnerabilities: {
    minimist: {
      name: "minimist",
      severity: "critical",
      range: "<0.2.4",
      nodes: ["node_modules/minimist"],
      isDirect: false,
      via: [
        { title: "Prototype Pollution in minimist", url: "https://github.com/advisories/GHSA-xvch-5gv4-984h", severity: "critical" },
        { title: "Older minimist issue", url: "https://github.com/advisories/GHSA-vh95-rmgr-6w4m", severity: "moderate" },
      ],
    },
    optimist: { name: "optimist", severity: "critical", range: ">=0.6.0", nodes: ["node_modules/optimist"], isDirect: false, via: ["minimist"] },
    forever: { name: "forever", severity: "critical", range: "*", nodes: ["node_modules/forever"], isDirect: true, via: ["optimist"] },
    grunt: {
      name: "grunt",
      severity: "high",
      range: "<1.5.3",
      nodes: ["node_modules/grunt"],
      isDirect: true,
      via: [{ title: "Race condition in grunt", url: "https://github.com/advisories/GHSA-rm36-94g8-835r", severity: "high" }],
    },
  },
};
const LOCK = {
  "": {},
  "node_modules/minimist": {},
  "node_modules/optimist": {},
  "node_modules/forever": {},
  "node_modules/grunt": { dev: true },
};

test("npm: dev-only packages are capped at low; production ones keep npm's severity", () => {
  const out = npmAuditAdapter(AUDIT, "package.json", "backend", LOCK);
  const grunt = out.find((f) => f.metadata.package === "grunt")!;
  assert.equal(grunt.severity, "low");
  assert.equal(grunt.metadata.devOnly, true);
  assert.equal(grunt.metadata.toolSeverity, "high");
  assert.match(grunt.title, /^Dev dependency grunt/);
  const minimist = out.find((f) => f.metadata.package === "minimist")!;
  assert.equal(minimist.severity, "critical");
  assert.equal(minimist.metadata.devOnly, false);
});

test("npm: propagation-only entries fold into the advisory, which names the direct dependency", () => {
  const out = npmAuditAdapter(AUDIT, "package.json", "backend", LOCK);
  assert.deepEqual(out.map((f) => f.metadata.package).sort(), ["grunt", "minimist"]);
  const minimist = out.find((f) => f.metadata.package === "minimist")!;
  assert.deepEqual(minimist.metadata.pulledInBy, ["forever"]);
  assert.match(minimist.tool_message, /pulled in by forever/);
  // Every advisory is kept (for KEV/EPSS), not just the first.
  assert.deepEqual(minimist.metadata.advisoryIds, ["GHSA-xvch-5gv4-984h", "GHSA-vh95-rmgr-6w4m"]);
  assert.match(minimist.title, /\(\+1 more advisory\)/);
});

test("npm: a package bundled inside a dev dependency is dev-only too", () => {
  const audit = {
    vulnerabilities: {
      tar: {
        name: "tar", severity: "high", range: "<6", isDirect: false,
        nodes: ["node_modules/npm/node_modules/tar"],
        via: [{ title: "tar issue", url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", severity: "high" }],
      },
    },
  };
  const lock = { "node_modules/npm": { dev: true }, "node_modules/npm/node_modules/tar": { inBundle: true } };
  assert.equal(npmAuditAdapter(audit, "package.json", "backend", lock)[0].severity, "low");
  const prodLock = { "node_modules/npm": {}, "node_modules/npm/node_modules/tar": { inBundle: true } };
  assert.equal(npmAuditAdapter(audit, "package.json", "backend", prodLock)[0].severity, "high");
});

test("npm: without a v2 lockfile nothing is treated as dev-only", () => {
  const out = npmAuditAdapter(AUDIT, "package.json", "backend", undefined);
  assert.equal(out.find((f) => f.metadata.package === "grunt")!.severity, "high");
});

test("osv: only dev/test lockfile groups count as non-production", () => {
  assert.equal(isNonProductionGroup(["dev"]), true);
  assert.equal(isNonProductionGroup(["dev", "test"]), true);
  assert.equal(isNonProductionGroup(["dev", "main"]), false);
  assert.equal(isNonProductionGroup(["optional"]), false);
  assert.equal(isNonProductionGroup(undefined), false);
});

// ------------------------------------------------------------ 2. KEV + EPSS

function dep(over: Partial<Finding> & { cve: string }): Finding {
  return {
    skill: "osv-pypi-pkg",
    category: "backend",
    finding_id: over.cve,
    rule_id: over.cve,
    severity: "high",
    confidence: "high",
    title: "pkg 1.0: bug",
    location: { file: "requirements.txt" },
    raw_snippet: null,
    tool_message: "pkg is affected.",
    metadata: { package: "pkg", version: "1.0" },
    ...over,
  };
}

test("intel: KEV raises to critical; low EPSS lowers high by one; dev-only stays low", () => {
  const exploited = dep({ cve: "CVE-2021-44228", severity: "medium" });
  const unlikely = dep({ cve: "CVE-2020-0001", severity: "critical" });
  const likely = dep({ cve: "CVE-2020-0002", severity: "high" });
  const devExploited = dep({ cve: "CVE-2021-44228", severity: "low", finding_id: "dev", metadata: { devOnly: true } });
  const intel = {
    kev: new Map([["CVE-2021-44228", { dateAdded: "2021-12-10", ransomware: true }]]),
    epss: new Map([
      ["CVE-2020-0001", { epss: 0.0004, percentile: 0.1 }],
      ["CVE-2020-0002", { epss: 0.42, percentile: 0.97 }],
    ]),
  };
  const s = applyExploitIntel([exploited, unlikely, likely, devExploited], intel, (f) => [f.rule_id], 0.01);
  assert.equal(exploited.severity, "critical");
  assert.match(exploited.title, /^Known exploited:/);
  assert.match(exploited.tool_message, /ransomware/);
  assert.equal(unlikely.severity, "high");
  assert.deepEqual(unlikely.metadata.loweredByEpss, { from: "critical", to: "high" });
  assert.equal(likely.severity, "high");
  assert.equal(likely.metadata.epss, 0.42);
  assert.equal(devExploited.severity, "low");
  assert.equal(devExploited.metadata.kev, true);
  assert.deepEqual(s, { kevMatches: 2, lowered: 1, scored: 2 });
});

// ------------------------------------------------------------ 3. deterministic filter

function code(over: Partial<Finding>): Finding {
  return {
    skill: "semgrep-x",
    category: "backend",
    finding_id: Math.random().toString(36),
    rule_id: "rule.a",
    severity: "high",
    confidence: "high",
    title: "t",
    location: { file: "app/routes/a.js", line_start: 10 },
    raw_snippet: null,
    tool_message: "m",
    metadata: { cwe: "CWE-95: Eval Injection" },
    ...over,
  };
}

test("filter: same file, line and CWE from different rules merge into one finding", () => {
  const a = code({ rule_id: "rule.a", severity: "medium" });
  const b = code({ rule_id: "rule.b", severity: "high" });
  const other = code({ rule_id: "rule.c", metadata: { cwe: "CWE-79" } });
  const { totalAfterFilter, groups, reductions } = filterFindings([a, b, other], "low");
  assert.equal(totalAfterFilter, 2);
  assert.equal(reductions.sameLineMerged, 1);
  const kept = groups.get("backend")!.find((f) => f.rule_id === "rule.b")!;
  assert.deepEqual(kept.metadata.alsoReportedBy, ["rule.a"]);
});

test("filter: test and vendored code is lowered to low, secrets are not", () => {
  const t = code({ location: { file: "test/e2e/login.spec.js", line_start: 1 } });
  const secret = code({ skill: "gitleaks-aws", location: { file: "test/fixtures/keys.js", line_start: 1 }, metadata: {} });
  filterFindings([t, secret], "low");
  assert.equal(t.severity, "low");
  assert.equal(t.metadata.nonProductionPath, true);
  assert.equal(secret.severity, "high");
});

test("filter: the same advisory from two manifests is reported once", () => {
  const a = dep({ cve: "CVE-2020-0002", finding_id: "a", location: { file: "svc-a/requirements.txt" } });
  const b = dep({ cve: "CVE-2020-0002", finding_id: "b", location: { file: "svc-b/requirements.txt" } });
  const { totalAfterFilter, groups } = filterFindings([a, b], "low");
  assert.equal(totalAfterFilter, 1);
  assert.deepEqual(groups.get("backend")![0].metadata.alsoIn, ["svc-b/requirements.txt"]);
});

test("filter: known-exploited and likely-exploited sort first within a severity", () => {
  const plain = dep({ cve: "CVE-1", finding_id: "1", metadata: { package: "p1" } });
  const likely = dep({ cve: "CVE-2", finding_id: "2", metadata: { package: "p2", epss: 0.5 } });
  const kev = dep({ cve: "CVE-3", finding_id: "3", metadata: { package: "p3", kev: true } });
  const sast = code({ finding_id: "4" });
  const order = filterFindings([plain, likely, sast, kev], "low").groups.get("backend")!.map((f) => f.finding_id);
  assert.deepEqual(order, ["3", "2", "4", "1"]);
});

test("non-production path detection", () => {
  for (const p of ["test/a.js", "src/__tests__/x.ts", "a.spec.ts", "vendor/lib.js", "public/js/jquery.min.js", "tests/test_api.py", "examples/demo.js"]) {
    assert.equal(isNonProductionPath(p), true, p);
  }
  for (const p of ["app/routes/contributions.js", "src/testing-utils-prod.ts", "server.js", "src/latest/x.js"]) {
    assert.equal(isNonProductionPath(p), false, p);
  }
});
