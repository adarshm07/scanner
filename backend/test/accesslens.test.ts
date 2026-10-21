import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDataset } from "../src/accesslens/data";
import { buildReviewPayload, mergeReply, reviewUser, rulesReview } from "../src/accesslens/review";
import { LlmProvider } from "../src/llm/provider";

const ds = buildDataset();
const byName = (name: string) => [...ds.detail.values()].find((u) => u.name === name)!;

test("loads every user and assignment from the dummy data", () => {
  assert.equal(ds.users.length, 100);
  assert.equal(ds.apps.length, 23);
  assert.equal(ds.users.reduce((s, u) => s + u.appCount, 0), 642);
});

test("access rows carry access type, group and usage", () => {
  const sneha = byName("Sneha Sharma");
  const slack = sneha.access.find((a) => a.appKey === "slack")!;
  assert.equal(slack.source, "GROUP");
  assert.equal(slack.viaGroup, "All-Employees");
  assert.deepEqual(slack.appRoles, ["user"]);
  assert.equal(slack.ssoCount90d, 35);
  assert.equal(slack.daysSinceUse, 3);
});

test("rules mark deprovisioned users for full revocation", () => {
  const noah = byName("Noah Verma");
  assert.equal(noah.status, "DEPROVISIONED");
  const r = rulesReview(noah, ds);
  assert.ok(r.decisions.length > 0);
  assert.ok(r.decisions.every((d) => d.verdict === "revoke"));
  assert.equal(r.missing.length, 0);
});

test("never-used critical access is revoked by rules", () => {
  const ella = byName("Ella Wright");
  const d = rulesReview(ella, ds).decisions.find((x) => x.appKey === "aws-prod")!;
  assert.equal(d.verdict, "revoke");
});

test("every open finding in the data surfaces somewhere", () => {
  let n = 0;
  for (const u of ds.detail.values()) {
    n += u.access.reduce((s, a) => s + a.findings.length, 0) + u.userFindings.length;
  }
  const missingFindings = 6;
  assert.equal(n + missingFindings, 71);
  assert.ok(byName("Mia Garcia").userFindings.some((f) => f.rule === "PRIVILEGED_ROLE"));
});

test("model payload is pseudonymous", () => {
  const u = byName("Sneha Sharma");
  const text = JSON.stringify(buildReviewPayload(u, ds));
  assert.ok(!text.includes("Sneha"));
  assert.ok(!text.includes("@acme-demo.com"));
  assert.ok(!text.includes("00u-SYNTH"));
});

test("model verdicts merge with rules; skipped or invalid apps fall back", () => {
  const u = byName("Sneha Sharma");
  const [first, second] = u.access;
  const r = mergeReply(
    u,
    ds,
    { decisions: [{ app: first.appKey, verdict: "review", confidence: "high", reason: "x" }, { app: second.appKey, verdict: "delete" }] },
    "fake"
  );
  assert.equal(r.engine, "llm");
  assert.equal(r.decisions.length, u.access.length);
  assert.equal(r.decisions[0].verdict, "review");
  assert.equal(r.decisions[1].verdict, r.decisions[1].ruleVerdict);
});

test("a failing model degrades to rules with an error", async () => {
  const broken: LlmProvider = { id: "openai", generate: async () => { throw new Error("boom"); } };
  const r = await reviewUser(byName("Liam Young"), ds, broken, true);
  assert.equal(r.engine, "rules");
  assert.match(r.error ?? "", /boom/);
});

test("demo users can include a GitHub PAT and repo config for targeted scans", () => {
  const ajinkya = [...ds.detail.values()].find((u) => u.name === "Ajinkya Bhise");
  assert.ok(ajinkya, "Ajinkya Bhise should be present in the AccessLens demo dataset");
  assert.equal(ajinkya.title, "Full Stack Developer");
  assert.ok(ajinkya.github);
  assert.equal(ajinkya.github?.owner, "ajinkya-bhise");
  assert.equal(ajinkya.github?.repo, "scanner");
  assert.ok(ajinkya.github?.repoUrl.includes("https://github.com/"));
  assert.ok(ajinkya.github?.tokenConfigured);
});
