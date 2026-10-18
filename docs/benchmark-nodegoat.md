# Benchmark: OWASP NodeGoat

NodeGoat is OWASP's deliberately vulnerable Node.js/Express app, so it comes with a known answer key. This page compares running the underlying scanners by hand with Scanner-X, with and without AI triage.

## Setup

- **Target:** `OWASP/NodeGoat`, default branch, October 2026.
- **Raw tools:** gitleaks (`detect --no-git`), semgrep with the community JavaScript rules, and `npm audit`, run directly. This is what you get without Scanner-X.
- **Scanner-X, no AI:** `scanner-x --path NodeGoat`, using the same semgrep rules plus Scanner-X's own rules, the dependency ranking and the noise filter. No API key.
- **Scanner-X + agent triage:** the same report, triaged the way the Claude Code / Codex skill does it. The coding agent reviews each finding against the code and `scanner-x apply-triage` merges its verdicts into the JSON and SARIF.

## Results

| | Raw tools | Scanner-X, no AI | Scanner-X + agent triage |
|---|---|---|---|
| Findings in the report | 169 | 99 | 97 |
| High/critical, which fail `--fail-on high` | 111 | 37 | **22** (8 code, 14 dependencies) |
| Known code bugs found (answer key below) | 6 of 10, plus CSRF at info level | **10 of 10** | **10 of 10** |
| Each finding explained, with a fix | no | tool message only | yes |
| Committed private key in output | redacted by gitleaks | masked (`MIIC****`) | masked |

Where the reduction comes from, without any AI. npm audit reports 149 vulnerable packages:
- 65 of them are only "vulnerable via" another package, so they repeat an advisory up the tree (45 at high or critical). They are folded into the root advisory, which names the direct dependency to upgrade.
- 50 of the remaining 84 are dev-only (grunt, mocha, cypress and the like; 32 at high or critical). They are capped at low and still listed.
- That leaves 34 production advisories, 28 of them high or critical.
- 8 semgrep hits on the same line and weakness are merged, and 1 duplicate is removed.

## Dependency reachability

Dependencies are their own report section. For each vulnerable package, Scanner-X finds where the app loads it, directly or through the direct dependency that pulls it in (from the lockfile's full dependency graph). The AI (built-in triage or the coding agent) then reads the advisory against those import sites and decides whether the vulnerable code is reachable. Unreachable advisories drop to low and stop failing the PR; nothing is removed.

On NodeGoat's 34 production advisories:

| | Before reachability | After agent reachability triage |
|---|---|---|
| Blocking dependency advisories | 27 | **8** |
| Reachable (fix first) | not known | 4: qs, body-parser, express (open redirect), marked |
| Unconfirmed, kept at full severity | 27 | 4: bson, fsevents, swig, kind-of |
| Used, but vulnerable code not reachable | not known | 21 (e.g. underscore: the app never calls `_.template`; proxy-addr: `trust proxy` isn't set) |
| Never loaded by the app | not known | 2 (nconf, i: only the unused forever CLI) |
| Blocking findings overall (code + dependencies) | 36 | **17** |

Without an AI, only the deterministic part applies: production packages nothing loads are lowered one level (2 here).

## Answer key: code-level bugs

| Bug | File | Raw tools | Scanner-X |
|---|---|---|---|
| Server-side JS injection (`eval` of request body) | `app/routes/contributions.js:32-34` | yes | yes, critical after triage |
| NoSQL injection via `$where` | `app/data/allocations-dao.js:77` | **no** | yes (Scanner-X rule) |
| Stored XSS: template autoescape disabled | `server.js:135` | **no** | yes (Scanner-X rule) |
| CSRF protection disabled | `server.js:78` | info only | yes (Scanner-X rule) |
| SSRF: user-controlled URL fetched | `app/routes/research.js:16` | **no** | yes (Scanner-X taint rule) |
| Open redirect | `app/routes/index.js:72` | yes | yes |
| ReDoS in validation regex | `app/routes/profile.js:61` | yes | yes |
| Insecure session cookie | `server.js:78` | yes (6 separate hits) | yes (1 merged finding) |
| Committed TLS private key | `artifacts/cert/server.key` | yes | yes |
| Hard-coded API key | `config/env/*.js` | yes | yes, triaged to low (test tooling) |

**Not found by any tool:** IDOR on `/allocations/:userId`, the missing admin check on `/benefits`, log injection, and plaintext password storage. These are logic bugs that need the code reviewed in context, which is what the agent-triage mode is for.

## Caveats

- semgrep ran with the community JavaScript rules from `github.com/semgrep/semgrep-rules`, because semgrep.dev wasn't reachable from the benchmark machine. With registry access, Scanner-X's default rulesets are broader.
- CISA KEV and EPSS ranking weren't applied, because api.osv.dev and api.first.org weren't reachable. With network access, known-exploited advisories rise to critical and those under 1% EPSS drop a level, so the 14 blocking dependency findings would shrink further.
- Trivy couldn't be downloaded on the benchmark machine, so this compares against the same scanners run by hand, not against Trivy. Run `trivy fs NodeGoat` next to Scanner-X on your own machine for that comparison.

## Reproduce

```bash
git clone --depth 1 https://github.com/OWASP/NodeGoat
node backend/dist/cli.js --path NodeGoat --json nodegoat.json --html nodegoat.html
# Agent triage: run the skill in Claude Code / Codex, or write verdicts and merge them:
node backend/dist/cli.js apply-triage --report nodegoat.json --triage verdicts.json --path NodeGoat
```
