import { test } from "node:test";
import assert from "node:assert/strict";
import { renderHtml } from "../src/orchestrator/html";
import { Report } from "../src/schema/finding";

function report(over: Partial<Report> = {}): Report {
  return {
    reportId: "r1",
    mode: "repo",
    target: "o/<script>alert(1)</script>",
    ref: "abc123def4567890",
    createdAt: "2026-10-17T00:00:00.000Z",
    executiveSummary: "",
    categories: [
      {
        category: "backend",
        findings: [
          {
            skill: "semgrep-x",
            category: "backend",
            finding_id: "f1",
            rule_id: "rule.<img src=x onerror=alert(1)>",
            severity: "high",
            confidence: "high",
            title: "SQL injection </summary><script>x()</script>",
            location: { file: "src/a b.js", line_start: 3 },
            raw_snippet: "q = '<script>'",
            tool_message: "msg",
            metadata: { advisoryUrl: "javascript:alert(1)" },
            triage: null,
          },
        ],
      },
    ],
    checks: [],
    stats: { totalRaw: 1, totalAfterFilter: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0 } },
    policy: { failOn: "high", passed: false, countAtOrAbove: 1 },
    ai: { provider: null, triageEnabled: false, llmFallbackUsed: false },
    ...over,
  };
}

test("html: everything from the report is escaped", () => {
  const h = renderHtml(report());
  assert.ok(!h.includes("<script>alert(1)"));
  assert.ok(!h.includes("<script>x()"));
  assert.ok(!h.includes("<img src=x"));
  assert.ok(h.includes("&lt;script&gt;"));
});

test("html: only http(s) links; files link to the commit with line anchors", () => {
  const h = renderHtml(report(), { linkBase: "https://github.com/o/r/blob/abc/" });
  assert.ok(!h.includes("javascript:"));
  assert.ok(h.includes('href="https://github.com/o/r/blob/abc/src/a%20b.js#L3"'));
});

test("html: the page allows no scripts or external loads", () => {
  assert.match(renderHtml(report()), /Content-Security-Policy" content="default-src 'none'/);
});
