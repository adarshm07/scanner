import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { checkTool, toolCheckTimeoutMs } from "../src/tools/util";

function fakeTool(body: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sx-tool-"));
  const bin = path.join(dir, "faketool");
  writeFileSync(bin, `#!/bin/sh\n${body}\n`);
  chmodSync(bin, 0o755);
  return bin;
}

test("a slow --version does not mark the tool as missing", { skip: process.platform === "win32" }, async () => {
  // Regression: semgrep takes several seconds to start; a timed-out probe used to skip all SAST.
  const bin = fakeTool("sleep 2; echo 1.0.0");
  const res = await checkTool(bin, undefined, 200);
  assert.equal(res.ok, true);
});

test("version output is returned for callers that parse it", { skip: process.platform === "win32" }, async () => {
  const bin = fakeTool("echo 'osv-scanner version: 2.1.0'");
  const res = await checkTool(bin);
  assert.ok(res.ok);
  if (res.ok) assert.match(res.output, /2\.1\.0/);
});

test("a missing tool is still reported as not installed", async () => {
  const res = await checkTool("definitely-not-a-real-scanner-x-tool");
  assert.deepEqual(res, { ok: false, error: "definitely-not-a-real-scanner-x-tool not installed" });
});

test("a failing --version is still reported", { skip: process.platform === "win32" }, async () => {
  const bin = fakeTool("echo boom >&2; exit 3");
  const res = await checkTool(bin);
  assert.equal(res.ok, false);
  if (!res.ok) assert.match(res.error, /exited 3: boom/);
});

test("probe timeout defaults to 60s and can be overridden", () => {
  assert.equal(toolCheckTimeoutMs({}), 60000);
  assert.equal(toolCheckTimeoutMs({ SCANNER_X_TOOL_CHECK_TIMEOUT_MS: "90000" }), 90000);
  assert.equal(toolCheckTimeoutMs({ SCANNER_X_TOOL_CHECK_TIMEOUT_MS: "nope" }), 60000);
});
