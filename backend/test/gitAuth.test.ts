import { test } from "node:test";
import assert from "node:assert/strict";
import { gitEnv, parseRepoToken, redactSecrets, resetGitCredentials } from "../src/tools/gitAuth";

const basicOf = (env: Record<string, string>) =>
  Buffer.from(env.GIT_CONFIG_VALUE_0.replace("AUTHORIZATION: basic ", ""), "base64").toString();

test("parseRepoToken: empty means no token", () => {
  assert.equal(parseRepoToken(undefined, undefined), undefined);
  assert.equal(parseRepoToken("", "x"), undefined);
  assert.equal(parseRepoToken("   ", undefined), undefined);
});

test("parseRepoToken: rejects header-breaking values", () => {
  assert.throws(() => parseRepoToken("abc\r\nX-Evil: 1", undefined));
  assert.throws(() => parseRepoToken("has space", undefined));
  assert.throws(() => parseRepoToken(123, undefined));
  assert.throws(() => parseRepoToken("tok", "bad:name"));
  assert.throws(() => parseRepoToken("x".repeat(1025), undefined));
});

test("parseRepoToken: trims and keeps optional username", () => {
  assert.deepEqual(parseRepoToken(" ghp_abc123 ", undefined), { token: "ghp_abc123" });
  assert.deepEqual(parseRepoToken("tok12345", " x-token-auth "), { token: "tok12345", username: "x-token-auth" });
});

test("gitEnv: per-scan token scoped to the repo host with host default username", () => {
  resetGitCredentials({});
  const gh = gitEnv("https://github.com/acme/private-repo", { token: "ghp_secret123" });
  assert.equal(gh.GIT_CONFIG_KEY_0, "http.https://github.com/.extraheader");
  assert.equal(basicOf(gh), "x-access-token:ghp_secret123");

  const bb = gitEnv("https://bitbucket.org/acme/repo", { token: "ATBBsecret1" });
  assert.equal(bb.GIT_CONFIG_KEY_0, "http.https://bitbucket.org/.extraheader");
  assert.equal(basicOf(bb), "x-bitbucket-api-token-auth:ATBBsecret1");

  const bbRepoToken = gitEnv("https://bitbucket.org/acme/repo", { token: "ATCTTsecret", username: "x-token-auth" });
  assert.equal(basicOf(bbRepoToken), "x-token-auth:ATCTTsecret");
  assert.equal(gh.GIT_TERMINAL_PROMPT, "0");
});

test("gitEnv: per-scan token wins over a server token; no token keeps old behaviour", () => {
  resetGitCredentials({ GITHUB_TOKEN: "server_token_1", GITHUB_OWNERS: "acme" });
  assert.equal(basicOf(gitEnv("https://github.com/acme/r", { token: "user_token_1" })), "x-access-token:user_token_1");
  assert.equal(basicOf(gitEnv("https://github.com/acme/r")), "x-access-token:server_token_1");
  assert.equal(gitEnv("https://github.com/other/r").GIT_CONFIG_COUNT, undefined);
  resetGitCredentials({});
});

test("redactSecrets: hides the per-scan token, raw and basic-encoded", () => {
  resetGitCredentials({});
  const t = { token: "ghp_supersecret99" };
  const basic = Buffer.from(`x-access-token:${t.token}`).toString("base64");
  const out = redactSecrets(`fatal: bad ${t.token} header ${basic}`, t);
  assert.ok(!out.includes(t.token));
  assert.ok(!out.includes(basic));
});
