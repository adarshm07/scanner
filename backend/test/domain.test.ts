import { test } from "node:test";
import assert from "node:assert/strict";
import { matchProbe, PROBES, scriptPaths } from "../src/tools/exposedFiles";
import { assessSubdomain, TakeoverDeps } from "../src/tools/takeover";
import { headerAdapter, HeaderData, PROBE_ORIGIN } from "../src/tools/headerCheck";
import { buildFixPlan, detectPlatform } from "../src/tools/fixConfig";
import { dnsAdapter } from "../src/tools/dnsCheck";

const probe = (path: string) => PROBES.find((p) => p.path === path)!;
const resp = (body: string | Buffer, contentType = "text/plain", status = 200) => ({
  status,
  contentType,
  body: Buffer.isBuffer(body) ? body : Buffer.from(body),
});

// ---------------------------------------------------------------- exposed files

test("exposed files: real .env matches; HTML catch-all pages don't", () => {
  assert.equal(matchProbe(probe(".env"), resp("DB_PASSWORD=x\nAPI_KEY=y\n"), null), true);
  const spa = resp("<!doctype html><html><body>App</body></html>", "text/html");
  assert.equal(matchProbe(probe(".env"), spa, spa), false);
  // HTML is rejected for non-HTML files even without a baseline
  assert.equal(matchProbe(probe(".env"), resp("<html>A=B</html>", "text/html"), null), false);
});

test("exposed files: a page identical to the random-path response is ignored", () => {
  const catchAll = resp("SOME_FLAG=1\n");
  assert.equal(matchProbe(probe(".env"), catchAll, catchAll), false);
});

test("exposed files: binary signatures and status pages", () => {
  assert.equal(matchProbe(probe("backup.zip"), resp(Buffer.from("PK\x03\x04rest", "binary"), "application/zip"), null), true);
  assert.equal(matchProbe(probe("backup.zip"), resp("not a zip"), null), false);
  assert.equal(matchProbe(probe("backup.sql"), resp("-- MySQL dump 10.13\nCREATE TABLE t (id int);"), null), true);
  assert.equal(matchProbe(probe("server-status"), resp("<html><h1>Apache Server Status for x</h1></html>", "text/html"), null), true);
  assert.equal(matchProbe(probe(".git/config"), resp("[core]\n\trepositoryformatversion = 0"), null), true);
  assert.equal(matchProbe(probe(".git/config"), resp("[core]", "text/plain", 404), null), false);
});

test("exposed files: only same-origin scripts are probed for source maps", () => {
  const html = '<script src="/static/main.js"></script><script src="https://cdn.other.com/x.js"></script><script src="app.js?v=2"></script>';
  assert.deepEqual(scriptPaths(html, "example.com"), ["static/main.js", "app.js"]);
});

// ---------------------------------------------------------------- takeover

function deps(cnames: Record<string, string>, nx: string[], pages: Record<string, string> = {}): TakeoverDeps {
  return {
    cname: async (n) => (cnames[n] ? [cnames[n]] : []),
    exists: async (n) => (nx.includes(n) ? "nx" : true),
    page: async (u) => pages[u] ?? null,
  };
}

test("takeover: unclaimed GitHub Pages site is high confidence", async () => {
  const r = await assessSubdomain(
    "docs.example.com",
    deps({ "docs.example.com": "example.github.io" }, [], { "https://docs.example.com/": "<h1>404</h1> There isn't a GitHub Pages site here." })
  );
  assert.equal(r?.severity, "high");
  assert.equal(r?.confidence, "high");
  assert.equal(r?.service, "GitHub Pages");
});

test("takeover: claimed service (normal page) is not flagged", async () => {
  const r = await assessSubdomain(
    "docs.example.com",
    deps({ "docs.example.com": "example.github.io" }, [], { "https://docs.example.com/": "<h1>Our docs</h1>" })
  );
  assert.equal(r, null);
});

test("takeover: deleted Azure app (NXDOMAIN) follows the CNAME chain", async () => {
  const r = await assessSubdomain(
    "app.example.com",
    deps({ "app.example.com": "edge.example.net", "edge.example.net": "old-app.azurewebsites.net" }, ["old-app.azurewebsites.net"])
  );
  assert.equal(r?.service, "Microsoft Azure");
  assert.equal(r?.severity, "high");
  assert.deepEqual(r?.cnameChain, ["edge.example.net", "old-app.azurewebsites.net"]);
});

test("takeover: generic dangling CNAME is medium/low; no CNAME is ignored", async () => {
  const dangling = await assessSubdomain("x.example.com", deps({ "x.example.com": "gone.unknown-host.io" }, ["gone.unknown-host.io"]));
  assert.equal(dangling?.severity, "medium");
  assert.equal(dangling?.confidence, "low");
  assert.equal(await assessSubdomain("www.example.com", deps({}, [])), null);
});

test("takeover: CNAME loops terminate", async () => {
  const r = await assessSubdomain("a.example.com", deps({ "a.example.com": "b.example.com", "b.example.com": "a.example.com" }, []));
  assert.equal(r, null);
});

// ---------------------------------------------------------------- headers

const base = (over: Partial<HeaderData> = {}): HeaderData => ({
  headers: {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
    "content-security-policy": "default-src 'self'",
  },
  setCookies: [],
  cors: { allowOrigin: null, allowCredentials: false },
  http: { result: "redirect-https", location: "https://example.com/", status: 301 },
  preload: null,
  ...over,
});
const rules = (r: { findings: { rule_id: string }[] }) => r.findings.map((f) => f.rule_id).sort();

test("headers: a well-configured site has no findings and no fix plan", () => {
  const r = headerAdapter("example.com", base());
  assert.deepEqual(rules(r), []);
  assert.equal(buildFixPlan("example.com", r.fix), null);
});

test("headers: CORS reflecting any origin with credentials is high", () => {
  const r = headerAdapter("example.com", base({ cors: { allowOrigin: PROBE_ORIGIN, allowCredentials: true } }));
  assert.equal(r.findings[0].rule_id, "cors-reflects-origin-credentials");
  assert.equal(r.findings[0].severity, "high");
  const noCreds = headerAdapter("example.com", base({ cors: { allowOrigin: PROBE_ORIGIN, allowCredentials: false } }));
  assert.equal(noCreds.findings[0].severity, "low");
  const star = headerAdapter("example.com", base({ cors: { allowOrigin: "*", allowCredentials: false } }));
  assert.deepEqual(rules(star), []);
});

test("headers: session cookie without flags is medium; tracking cookie only needs Secure", () => {
  const r = headerAdapter("example.com", base({ setCookies: ["sessionid=abc; Path=/", "_ga=1; Path=/; Secure"] }));
  assert.deepEqual(rules(r), ["cookie-flags-sessionid"]);
  assert.equal(r.findings[0].severity, "medium");
  assert.match(r.findings[0].title, /Secure, HttpOnly, SameSite/);
  const ok = headerAdapter("example.com", base({ setCookies: ["sid=1; Secure; HttpOnly; SameSite=Lax"] }));
  assert.deepEqual(rules(ok), []);
});

test("headers: plain HTTP, weak HSTS, missing Permissions-Policy, X-Powered-By", () => {
  const h = { ...base().headers, "strict-transport-security": "max-age=600", "x-powered-by": "Express" };
  delete (h as Record<string, string>)["permissions-policy"];
  const r = headerAdapter("example.com", base({ headers: h, http: { result: "served", status: 200 } }));
  assert.deepEqual(rules(r), ["missing-permissions-policy", "no-https-redirect", "weak-hsts", "x-powered-by-disclosure"]);
});

test("headers: HSTS preload status is reported, never a finding", () => {
  const r = headerAdapter("example.com", base({ preload: "preloaded" }));
  assert.equal(r.checks.find((c) => c.name === "HSTS preload")?.observed, "on the browser preload list");
  assert.deepEqual(rules(r), []);
});

// ---------------------------------------------------------------- fix snippets

test("fixes: nginx detected from Server header and covers every change", () => {
  const h: Record<string, string> = { server: "nginx/1.18.0" };
  const r = headerAdapter("example.com", base({ headers: h, setCookies: ["sessionid=1"], http: { result: "served", status: 200 } }));
  const plan = buildFixPlan("example.com", r.fix)!;
  assert.equal(plan.detected, "nginx");
  assert.equal(plan.platforms[0].id, "nginx");
  const s = plan.platforms[0].snippet;
  for (const needle of [
    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    "add_header X-Frame-Options",
    "add_header Permissions-Policy",
    "Content-Security-Policy-Report-Only",
    "server_tokens off;",
    "proxy_cookie_flags",
    "return 301 https://$host$request_uri;",
  ]) assert.ok(s.includes(needle), `nginx snippet missing: ${needle}`);
  assert.equal(plan.platforms.length, 8);
});

test("fixes: platform detection", () => {
  const f = (server: string | null, poweredBy: string | null, hints: string[] = []) =>
    detectPlatform({ server, poweredBy, platformHints: hints, missingHeaders: [], weakHsts: false, hideServerVersion: false, hidePoweredBy: false, httpRedirect: false, cookies: [], csp: false })?.id ?? null;
  assert.equal(f("Vercel", "Next.js"), "vercel");
  assert.equal(f(null, "Next.js"), "nextjs");
  assert.equal(f(null, "Express"), "express");
  assert.equal(f("Apache/2.4.41 (Ubuntu)", null), "apache");
  assert.equal(f("cloudflare", null), "cloudflare");
  assert.equal(f("Microsoft-IIS/10.0", null), "iis");
  assert.equal(f(null, null), null);
});

test("fixes: vercel.json is valid JSON with the missing headers", () => {
  const r = headerAdapter("example.com", base({ headers: { server: "Vercel" } }));
  const vercel = buildFixPlan("example.com", r.fix)!.platforms.find((p) => p.id === "vercel")!;
  const json = JSON.parse(vercel.snippet);
  const keys = json.headers[0].headers.map((h: { key: string }) => h.key);
  assert.ok(keys.includes("Strict-Transport-Security") && keys.includes("X-Content-Type-Options"));
});

// ---------------------------------------------------------------- DNS

test("dns: CAA, DNSSEC and MTA-STS", () => {
  const ok = { hasSpf: true, spfRecord: "v=spf1 -all", hasDmarc: true, dmarcPolicy: "reject", hasDkim: true };
  const bad = dnsAdapter("example.com", { ...ok, hasMx: true, mtaSts: "missing", caa: null, dnssec: false });
  assert.deepEqual(bad.findings.map((f) => f.rule_id).sort(), ["caa-missing", "dnssec-disabled", "mta-sts-missing"]);
  const good = dnsAdapter("example.com", { ...ok, hasMx: true, mtaSts: "enforce", caa: { name: "example.com", issuers: ["letsencrypt.org"] }, dnssec: true });
  assert.deepEqual(good.findings, []);
  const noMail = dnsAdapter("example.com", { ...ok, hasMx: false, caa: { name: "example.com", issuers: [] }, dnssec: null });
  assert.deepEqual(noMail.findings, []);
  assert.equal(noMail.checks.find((c) => c.name === "DNSSEC")?.result, "inconclusive");
});
