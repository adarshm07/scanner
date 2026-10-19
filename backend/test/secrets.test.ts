import { test } from "node:test";
import assert from "node:assert/strict";
import { maskText, scrubKeyMaterial } from "../src/tools/secrets";

const KEY = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIICXgIBAAKBgQCfn8uP4FuHaaAPrMkcl1fNMQM5EGMT4nnNSVoaEVdiDLc6P0mC",
  "AZtUO9W0OjWow+TwGk3HkqoSJOA9KRMrzK7MtEKfwNgzpsHo4m+mHaPg5DUyicnU",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

test("multi-line secrets are masked inside line-numbered snippets", () => {
  const snippet = KEY.split("\n").map((l, i) => `${i + 1}: ${l}`).join("\n");
  const out = maskText(snippet, [KEY]);
  assert.ok(!out.includes("MIICXgIBAAKBgQCfn8uP4"), out);
  assert.ok(!out.includes("AZtUO9W0OjWow"), out);
  assert.match(out, /2: MIIC\*\*\*\*/);
  // Armor lines stay readable, so a reviewer still sees what kind of secret it was.
  assert.match(out, /1: -----BEGIN RSA PRIVATE KEY-----/);
});

test("multi-line secrets with CRLF line endings are masked", () => {
  const crlfKey = KEY.split("\n").join("\r\n");
  const snippet = KEY.split("\n").map((l, i) => `${i + 1}: ${l}`).join("\n");
  const out = maskText(snippet, [crlfKey]);
  assert.ok(!out.includes("MIICXgIBAAKBgQCfn8uP4"), out);
});

test("single-line secrets are still masked whole", () => {
  const out = maskText('zapApiKey: "v9dn0balpqas1pcc281tn5ood1",', ["v9dn0balpqas1pcc281tn5ood1"]);
  assert.equal(out, 'zapApiKey: "v9dn****",');
});

test("fragments of a secret elsewhere in the snippet are masked too", () => {
  // The leak that tripped the gateway's secret detector: test assertions quoting part of the key.
  const snippet = [
    `15:   assert.ok(!out.includes("MIICXgIBAAKBgQCfn8uP4"), out);`,
    `16:   assert.ok(!out.includes("AZtUO9W0OjWow"), out);`,
    `17:   const unrelated = "functionNameThatIsLong";`,
  ].join("\n");
  const out = maskText(snippet, [KEY]);
  assert.ok(!out.includes("MIICXgIBAAKBgQCfn8uP4"), out);
  assert.ok(!out.includes("AZtUO9W0OjWow"), out);
  assert.match(out, /functionNameThatIsLong/);
});

test("scrubKeyMaterial redacts unreported key material but keeps line structure", () => {
  const text = KEY.split("\n").map((l, i) => `${i + 1}: ${l}`).join("\n");
  const out = scrubKeyMaterial(text);
  assert.ok(!/PRIVATE KEY/.test(out), out);
  assert.ok(!out.includes("MIICXgIBAAKBgQCfn8uP4"), out);
  assert.equal(out.split("\n").length, 4);
  assert.match(out, /^1: \[private key start\]$/m);
});
