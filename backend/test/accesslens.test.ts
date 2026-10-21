import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import { buildDataset, dataDir } from "../src/accesslens/data";
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

test("rules computed from raw Okta data reproduce the answer key exactly", () => {
  // Every flag comes from the engine; findings.json is not read. Demo users added after the
  // seed (demo_users.json) aren't in the answer key, so only seed users are compared.
  const seedUsers = new Set(
    (JSON.parse(fs.readFileSync(path.join(dataDir(), "users.json"), "utf8")) as { _id: number }[]).map((u) => u._id)
  );
  const got = new Map<string, number>();
  for (const u of ds.detail.values()) {
    if (!seedUsers.has(u.id)) continue;
    for (const a of u.access) for (const f of a.findings) got.set(`${u.name}|${f.appKey}|${f.rule}`, f.riskScore);
    for (const f of u.userFindings) got.set(`${u.name}|${f.appKey}|${f.rule}`, f.riskScore);
    for (const m of u.missing) got.set(`${u.name}|${m.appKey}|MISSING_ACCESS`, NaN);
  }
  const expected = JSON.parse(fs.readFileSync(path.join(dataDir(), "expected_findings.json"), "utf8")) as {
    user: string;
    app: string | null;
    rule: string;
    risk_score: number;
  }[];
  assert.equal(expected.length, 71);
  for (const e of expected) {
    const key = `${e.user}|${e.app}|${e.rule}`;
    assert.ok(got.has(key), `missing ${key}`);
    const score = got.get(key)!;
    if (!Number.isNaN(score)) assert.equal(score, e.risk_score, `score for ${key}`);
    got.delete(key);
  }
  assert.deepEqual([...got.keys()], [], "no findings beyond the answer key");
});

test("users with no department get a cohort inferred from their apps", () => {
  const seedCohort = new Map(
    (JSON.parse(fs.readFileSync(path.join(dataDir(), "user_cohorts.json"), "utf8")) as { user_id: number; cohort_id: number }[]).map(
      (c) => [c.user_id, c.cohort_id]
    )
  );
  const noDept = [...ds.detail.values()].filter((u) => !u.department && seedCohort.has(u.id));
  assert.equal(noDept.length, 23);
  assert.ok(noDept.every((u) => u.cohort?.inferred));
  // Same grouping as the seed for 22 of 23. User 94 holds GitHub, which every Web engineer has
  // and no Product person has, so the apps point to Web rather than the seed's Product label.
  const seedLabelOf = new Map<number, string>();
  for (const u of ds.detail.values()) if (u.department && u.cohort) seedLabelOf.set(seedCohort.get(u.id)!, u.cohort.label);
  const agree = noDept.filter((u) => seedLabelOf.get(seedCohort.get(u.id)!) === u.cohort?.label);
  assert.equal(agree.length, 22);
  assert.equal(byName("Mia Garcia").cohort?.label, "Marketing");
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
