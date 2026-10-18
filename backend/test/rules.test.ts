import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "fs";
import path from "path";
import { runCommand } from "../src/tools/util";
import { classifySemgrepFailure } from "../src/tools/semgrep";

/**
 * Scanner-X's own semgrep rules against annotated fixtures: a `// ruleid: <id>` comment
 * means the next line must match <id>; `// ok: <id>` means it must not. Skipped when
 * semgrep isn't installed.
 */

const RULES = path.resolve(__dirname, "../rules/scanner-x.yml");
const FIXTURES = path.resolve(__dirname, "../rules/fixtures");
const ENV = { SEMGREP_ENABLE_VERSION_CHECK: "0", SEMGREP_SEND_METRICS: "off" };

test("scanner-x semgrep rules match their fixtures", async (t) => {
  const version = await runCommand("semgrep", ["--version"], { timeoutMs: 60000, env: ENV });
  if (version.spawnError || version.code !== 0) return t.skip("semgrep not installed");

  const res = await runCommand("semgrep", ["--config", RULES, "--json", "--metrics=off", FIXTURES], {
    timeoutMs: 180000,
    env: ENV,
  });
  const out = JSON.parse(res.stdout) as {
    results: { path: string; start: { line: number }; check_id: string }[];
    errors: { message?: string }[];
  };
  assert.deepEqual(out.errors.map((e) => e.message), [], "rule errors");
  const ruleName = (id: string) => id.slice(id.indexOf("scanner-x."));
  const actual = new Set(out.results.map((r) => `${path.basename(r.path)}:${r.start.line}:${ruleName(r.check_id)}`));

  const expected = new Set<string>();
  const forbidden = new Set<string>();
  for (const file of await fs.readdir(FIXTURES)) {
    const lines = (await fs.readFile(path.join(FIXTURES, file), "utf8")).split("\n");
    lines.forEach((line, i) => {
      const m = line.match(/\/\/\s*(ruleid|ok):\s*(\S+)/);
      if (!m) return;
      const key = `${file}:${i + 2}:${m[2]}`;
      (m[1] === "ruleid" ? expected : forbidden).add(key);
    });
  }
  assert.ok(expected.size >= 6, "fixtures have annotations");
  for (const e of expected) assert.ok(actual.has(e), `missed: ${e}`);
  for (const f of forbidden) assert.ok(!actual.has(f), `false positive: ${f}`);
  for (const a of actual) assert.ok(expected.has(a), `unexpected match: ${a}`);
});

test("semgrep failures are explained, not just an exit code", () => {
  const offline = classifySemgrepFailure({
    code: 2,
    stdout: "",
    stderr:
      "HTTPSConnectionPool(host='semgrep.dev', port=443): Max retries exceeded with url: /c/p/security-audit (Caused by ProxyError('Unable to connect to proxy'))\nTraceback (most recent call last):\n  ...",
  });
  assert.match(offline, /couldn't download its rules from semgrep\.dev/);
  assert.match(offline, /SEMGREP_CONFIG/);

  const badConfig = classifySemgrepFailure({
    code: 7,
    stdout: "",
    stderr: "[ERROR] Invalid configuration file found: /nope/rules.yml does not exist",
  });
  assert.match(badConfig, /SEMGREP_CONFIG|rules/i);

  const exec = classifySemgrepFailure({ code: null, stdout: "", stderr: "", spawnError: "spawn pysemgrep ENOENT" });
  assert.match(exec, /pysemgrep/);
});
