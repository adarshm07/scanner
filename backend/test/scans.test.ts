import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

// State goes to a throwaway folder; set before scans.ts is loaded.
process.env.ACCESSLENS_STATE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "accesslens-state-"));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const scans = require("../src/accesslens/scans") as typeof import("../src/accesslens/scans");
const base = { ...scans.DEFAULT_SCHEDULE, timezone: "Asia/Kolkata" };

test("daily, weekly and custom schedules map to cron", () => {
  assert.equal(scans.cronFor({ ...base, frequency: "daily", time: "09:05" }), "5 9 * * *");
  assert.equal(scans.cronFor({ ...base, frequency: "weekly", time: "18:30", weekday: 5 }), "30 18 * * 5");
  assert.equal(scans.cronFor({ ...base, frequency: "custom", cron: " 0 6 1 * * " }), "0 6 1 * *");
});

test("invalid schedules are rejected", () => {
  assert.match(scans.validateSchedule({ ...base, time: "25:00" })!, /HH:MM/);
  assert.match(scans.validateSchedule({ ...base, frequency: "custom", cron: "* * *" })!, /five-field/);
  assert.match(scans.validateSchedule({ ...base, frequency: "custom", cron: "*/5 * * * *" })!, /once an hour/);
  assert.match(scans.validateSchedule({ ...base, timezone: "Mars/Olympus" })!, /time zone/);
  assert.equal(scans.validateSchedule({ ...base, frequency: "weekly", weekday: 1 }), null);
});

test("next run follows the schedule's time zone", () => {
  const runs = scans.nextRuns({ ...base, enabled: true, frequency: "daily", time: "09:00" }, 2);
  assert.equal(runs.length, 2);
  // 09:00 in Asia/Kolkata is 03:30 UTC.
  assert.ok(runs.every((r) => r.endsWith("T03:30:00.000Z")));
});

async function waitFor(id: string) {
  for (let i = 0; i < 200; i++) {
    const r = scans.getRun(id)!;
    if (r.status !== "running") return r;
    await new Promise((res) => setTimeout(res, 25));
  }
  throw new Error("scan did not finish");
}

test("a rules-only scan reviews every user and diffs against the previous scan", async () => {
  const first = await waitFor((await scans.startScan("manual", { provider: "rules", scope: "all" })).id);
  assert.equal(first.status, "done");
  assert.equal(first.usersReviewed, first.usersTotal);
  assert.ok(first.findingsTotal > 0);
  assert.equal(first.previousRunId, null);
  assert.equal(first.summary?.engine, "rules");

  const second = await waitFor((await scans.startScan("manual", { provider: "rules", scope: "flagged" })).id);
  assert.equal(second.previousRunId, first.id);
  assert.equal(second.newFindings.length, 0);
  assert.equal(second.resolvedFindings.length, 0);
  assert.equal(second.usersReviewed, second.flaggedUsers);
  assert.equal(scans.listRuns().length, 2);
});

test("only one scan runs at a time", async () => {
  const run = await scans.startScan("manual", { provider: "rules" });
  await assert.rejects(scans.startScan("manual", { provider: "rules" }), /already running/);
  await waitFor(run.id);
});
