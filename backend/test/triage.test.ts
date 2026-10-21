import { test } from "node:test";
import assert from "node:assert/strict";
import { Finding } from "../src/schema/finding";
import { LlmMessage, LlmProvider, GuardrailBlockedError } from "../src/llm/provider";
import { buildPayload, isRuleTestFixture, isGuardrailBlock, isSplittable, triageCategory } from "../src/orchestrator/triage";
import { normalizeRuleId } from "../src/tools/semgrep";

const FIXTURE_SNIPPET = [
  "8: const app = express();",
  "9: // ruleid: scanner-x.express-session-without-csrf",
  '10: app.use(session({ secret: "s", resave: false }));',
  "11: ",
  "12: // ruleid: scanner-x.template-autoescape-disabled",
  "13: swig.setDefaults({ autoescape: false });",
].join("\n");

function finding(over: Partial<Finding> & { finding_id: string }): Finding {
  return {
    skill: "semgrep-rule",
    category: "backend",
    rule_id: "rule",
    severity: "medium",
    confidence: "medium",
    title: "Something is wrong. A long second sentence explaining how an attacker abuses it.",
    location: { file: "src/a.ts", line_start: 2, line_end: 2 },
    raw_snippet: "1: a\n2: b\n3: c",
    tool_message: "Something is wrong. A long second sentence explaining how an attacker abuses it.",
    metadata: { cwe: "CWE-1" },
    ...over,
  };
}

test("semgrep rule ids lose the local config path prefix", () => {
  assert.equal(
    normalizeRuleId("Users.adarsh.m.Work.scannerX.backend.rules.scanner-x.nosql-where-injection"),
    "scanner-x.nosql-where-injection"
  );
  assert.equal(normalizeRuleId("scanner-x.ssrf-user-controlled-url"), "scanner-x.ssrf-user-controlled-url");
  assert.equal(
    normalizeRuleId("javascript.lang.security.detect-child-process.detect-child-process"),
    "javascript.lang.security.detect-child-process.detect-child-process"
  );
});

test("payload sends each file's code once and drops the scanner's prose", () => {
  const a = finding({ finding_id: "a", raw_snippet: "1: a\n2: b\n3: c" });
  const b = finding({ finding_id: "b", location: { file: "src/a.ts", line_start: 3 }, raw_snippet: "2: b\n3: c\n4: d" });
  const c = finding({ finding_id: "c", location: { file: "src/a.ts", line_start: 9 }, raw_snippet: "9: z" });
  const p = buildPayload([a, b, c], false);
  assert.deepEqual(Object.keys(p.files), ["src/a.ts"]);
  assert.equal(p.files["src/a.ts"], "1: a\n2: b\n3: c\n4: d\n...\n9: z");
  for (const f of p.findings) {
    assert.ok(!("tool_message" in f));
    assert.ok(!("raw_snippet" in f));
    assert.equal(f.title, "Something is wrong.");
  }
  // Dependency triage needs the advisory text.
  assert.ok("tool_message" in buildPayload([a], true).findings[0]);
});

test("semgrep rule-test fixtures are recognized", () => {
  assert.ok(isRuleTestFixture(finding({ finding_id: "f", raw_snippet: FIXTURE_SNIPPET, metadata: { nonProductionPath: true } })));
  // Annotations alone aren't enough in shipped code, and test code without them goes to the model.
  assert.ok(!isRuleTestFixture(finding({ finding_id: "g", raw_snippet: FIXTURE_SNIPPET })));
  assert.ok(!isRuleTestFixture(finding({ finding_id: "h", metadata: { nonProductionPath: true } })));
});

test("guardrail errors are told apart from other failures", () => {
  assert.ok(isGuardrailBlock(new GuardrailBlockedError("response blocked")));
  assert.ok(isGuardrailBlock(Object.assign(new Error("400 Request blocked by guardrail: secrets-detection"), { status: 400 })));
  assert.ok(!isGuardrailBlock(Object.assign(new Error("401 Invalid API key"), { status: 401 })));
  assert.ok(!isGuardrailBlock(new Error("Request timed out.")));
});

class FakeProvider implements LlmProvider {
  readonly id = "openai" as const;
  calls: string[] = [];
  constructor(private blockIf: (user: string) => boolean) {}
  async generate(msg: LlmMessage): Promise<string> {
    this.calls.push(msg.user);
    if (this.blockIf(msg.user)) throw Object.assign(new Error("400 Input blocked by guardrail"), { status: 400 });
    const ids = [...msg.user.matchAll(/"finding_id": "([^"]+)"/g)].map((m) => m[1]);
    return JSON.stringify({
      results: ids.map((id) => ({
        finding_id: id,
        verdict: "true_positive",
        adjusted_severity: "medium",
        explanation: `Model explanation for ${id} with context.`,
        suggested_fix: `1. Fix ${id}.\n2. Re-run the scan.`,
      })),
    });
  }
}

test("a blocked finding is isolated instead of failing its whole batch", async () => {
  const findings = ["a", "b", "c", "d", "e"].map((id) => finding({ finding_id: id, location: { file: `src/${id}.ts`, line_start: 1 }, raw_snippet: `1: code ${id}` }));
  // Blocked by the finding itself, so even the minimal retry is refused.
  const provider = new FakeProvider((u) => u.includes('"finding_id": "c"'));
  const { results, llmFallbackUsed } = await triageCategory(provider, "backend", "repo", findings);
  assert.ok(llmFallbackUsed);
  for (const id of ["a", "b", "d", "e"]) assert.equal(results.get(id)?.verdict, "true_positive", id);
  assert.equal(results.get("c")?.verdict, "needs_review");
  assert.match(results.get("c")!.explanation, /guardrail/);
});

test("a blocked finding is retried without its code and still gets a model verdict", async () => {
  const findings = ["a", "b", "c"].map((id) => finding({ finding_id: id, location: { file: `src/${id}.ts`, line_start: 1 }, raw_snippet: `1: code ${id}` }));
  findings[1].raw_snippet = "1: code PAYLOAD";
  const provider = new FakeProvider((u) => u.includes("PAYLOAD"));
  const { results, llmFallbackUsed } = await triageCategory(provider, "backend", "repo", findings);
  assert.ok(!llmFallbackUsed);
  for (const id of ["a", "b", "c"]) assert.equal(results.get(id)?.verdict, "true_positive", id);
  const minimalCall = provider.calls.find((u) => u.includes("No code or advisory text"));
  assert.ok(minimalCall && !minimalCall.includes("PAYLOAD"));
});

test("a gateway refusal returned as plain text (200, not JSON) is split, not a whole-batch fallback", async () => {
  const findings = ["a", "b", "c", "d"].map((id) => finding({ finding_id: id, location: { file: `src/${id}.ts`, line_start: 1 }, raw_snippet: `1: code ${id}` }));
  findings[3].raw_snippet = "1: code BAD";
  const provider: LlmProvider = {
    id: "openai",
    async generate(msg) {
      if (msg.user.includes('"finding_id": "d"')) return "Sorry, the model cannot answer this question.";
      return FakeProvider.prototype.generate.call(new FakeProvider(() => false), msg);
    },
  };
  const { results } = await triageCategory(provider, "backend", "repo", findings);
  for (const id of ["a", "b", "c"]) assert.equal(results.get(id)?.verdict, "true_positive", id);
  assert.equal(results.get("d")?.verdict, "needs_review");
});

test("unrecognised 400s split; auth, rate-limit and timeout errors do not", () => {
  assert.ok(isSplittable(Object.assign(new Error("400 Request rejected"), { status: 400 })));
  assert.ok(isSplittable(new Error("LLM did not return valid JSON")));
  assert.ok(!isSplittable(Object.assign(new Error("401 Invalid API key"), { status: 401 })));
  assert.ok(!isSplittable(Object.assign(new Error("429 Too many requests"), { status: 429 })));
  assert.ok(!isSplittable(new Error("Request timed out.")));
});

test("rule-test fixtures never reach the model", async () => {
  const fixture = finding({ finding_id: "fx", raw_snippet: FIXTURE_SNIPPET, metadata: { nonProductionPath: true } });
  const real = finding({ finding_id: "real" });
  const provider = new FakeProvider(() => false);
  const { results } = await triageCategory(provider, "backend", "repo", [fixture, real]);
  assert.equal(results.get("fx")?.verdict, "false_positive");
  assert.equal(results.get("real")?.verdict, "true_positive");
  assert.equal(provider.calls.length, 1);
  assert.ok(!provider.calls[0].includes("swig.setDefaults"));
});

test("model errors are reported to the scan log", async () => {
  const findings = ["a", "b"].map((id) => finding({ finding_id: id, location: { file: `src/${id}.ts`, line_start: 1 }, raw_snippet: `1: code ${id}` }));
  const provider = new FakeProvider((u) => u.includes('"finding_id": "b"'));
  const logs: [string, string][] = [];
  await triageCategory(provider, "backend", "repo", findings, (level, message) => logs.push([level, message]));
  assert.ok(logs.some(([l, m]) => l === "warn" && /splitting/.test(m)));
  assert.ok(logs.some(([l, m]) => l === "error" && /src\/b\.ts:1/.test(m) && /blocked by guardrail/.test(m)));
});
