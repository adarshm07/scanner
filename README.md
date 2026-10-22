# Scanner-X

AI-assisted security review that composes **deterministic, open-source scanning
tools** with a **thin LLM triage layer**. Two entry points share one backend:

1. **PR / Agent Skill** (`/scanner-x`) — interactive, scope-driven scans for repos and PRs.
2. **Domain Recon Web App** — security report for a domain you own: TLS, headers, cookies, CORS, DNS (email auth, CAA, DNSSEC), subdomain takeover and exposed files, with copy-paste fixes for your server.

**On OWASP NodeGoat:** the same scanners run by hand give 169 findings, 111 of them blocking, and find 6 of the 10 known code bugs. Scanner-X with no AI key gives 99 findings, 37 blocking, and finds all 10; with agent triage, 22 are blocking. See [the benchmark](docs/benchmark-nodegoat.md).

## Core design principle

Deterministic tools do **all** detection. The LLM (Gemini or Claude, selectable)
is used **only** for triage, prioritization, explanation, and the executive
summary — never for raw code/log analysis at scale. Findings are reduced to a
small structured JSON payload
([the universal `Finding` schema](backend/src/schema/finding.ts)) before any LLM
call. Snippets are hydrated (~20 lines) **only for findings that survive
filtering**, which is the main token-saving step.

## Pipeline

```
runPipeline  →  filterFindings  →  hydrate snippets  →  triage (batched LLM)  →  report (+1 summary LLM call)
   collect        dedupe +            ~20-line window     ≤20 findings/call        merge in code, one
   Finding[]      severity floor      (survivors only)     cached by finding_id     creative-writing call
```

- [`orchestrator/runPipeline.ts`](backend/src/orchestrator/runPipeline.ts) — runs tool adapters in parallel.
- [`orchestrator/filterFindings.ts`](backend/src/orchestrator/filterFindings.ts) — dedupe + severity floor + group by category.
- [`orchestrator/hydrate.ts`](backend/src/orchestrator/hydrate.ts) — snippet hydration for survivors only.
- [`orchestrator/triage.ts`](backend/src/orchestrator/triage.ts) — one batched LLM call per category, cached by `finding_id`.
- [`orchestrator/report.ts`](backend/src/orchestrator/report.ts) — assembles report in code + one executive-summary LLM call.

## Deterministic tools

| Mode | Tool | Adapter |
| --- | --- | --- |
| repo | gitleaks (secrets) | [`tools/gitleaks.ts`](backend/src/tools/gitleaks.ts) |
| repo | semgrep (`p/security-audit`) | [`tools/semgrep.ts`](backend/src/tools/semgrep.ts) |
| repo | npm audit (JavaScript deps) | [`tools/npmAudit.ts`](backend/src/tools/npmAudit.ts) |
| repo | OSV-Scanner (Python, Java, Rust, Go, Ruby, PHP, .NET, yarn/pnpm deps) | [`tools/osvScanner.ts`](backend/src/tools/osvScanner.ts) |
| domain | TLS / cert chain (+ SSL Labs) | [`tools/tlsCheck.ts`](backend/src/tools/tlsCheck.ts) |
| domain | HTTP headers, cookie flags, CORS, HTTP→HTTPS redirect, HSTS preload | [`tools/headerCheck.ts`](backend/src/tools/headerCheck.ts) |
| domain | Fix snippets (nginx, Apache, IIS, Express, Next.js, Vercel, Netlify, Cloudflare) | [`tools/fixConfig.ts`](backend/src/tools/fixConfig.ts) |
| domain | Content-Security-Policy grading | [`tools/cspCheck.ts`](backend/src/tools/cspCheck.ts) |
| domain | DNS: SPF, DKIM, DMARC, MTA-STS, CAA, DNSSEC | [`tools/dnsCheck.ts`](backend/src/tools/dnsCheck.ts) |
| domain | CT subdomains (crt.sh) + subdomain takeover | [`tools/subdomainCheck.ts`](backend/src/tools/subdomainCheck.ts), [`tools/takeover.ts`](backend/src/tools/takeover.ts) |
| domain | Exposed files (~30 paths + source maps, catch-all aware) | [`tools/exposedFiles.ts`](backend/src/tools/exposedFiles.ts) |

Unit tests for the domain checks: `cd backend && npm test`.

Each adapter exposes `toolNameAdapter(rawOutput): Finding[]`, isolating all
tool-specific parsing. A repo tool whose CLI isn't installed contributes no
findings. If the clone fails or the repo has no scannable code, the report has
zero findings, a warning, and a failed policy (`reason: "scan incomplete"`).

- **Dependencies in other languages:** OSV-Scanner reads `requirements*.txt`,
  `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pom.xml`, `gradle.lockfile`, `Cargo.lock`,
  `go.mod`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`, `pubspec.lock`,
  `yarn.lock` and `pnpm-lock.yaml`, and checks them against the OSV.dev database.
  Aliased advisories (GHSA, CVE, PYSEC, RUSTSEC) are merged into one finding with
  the fixed versions. A manifest it can't read without a lockfile (e.g. a Rust
  library with only `Cargo.toml`) is listed as a note, not silently skipped.
- **Dependencies without a lockfile:** when a `package.json` has no
  `package-lock.json`, the scanner resolves one in a temporary directory
  (`npm install --package-lock-only --ignore-scripts`, registry pinned; the repo is
  never modified) and audits that. Those findings are tagged `lockfileGenerated`,
  since installed versions may differ.
- **TLS evidence:** the TLS check captures the full certificate chain, checks the
  hostname, and diagnoses why trust failed: self-signed, missing intermediate,
  private CA, expired chain certificate, or an HTTPS-inspecting proxy on the
  scanner's own network (Zscaler, Netskope, antivirus, ...). Proxy interception is
  reported as an *inconclusive* check with a note, not as a finding. Findings show
  the evidence and a ready-to-run `openssl` command to verify it.

## Running

### Backend

```bash
cd backend
npm install
cp .env.example .env   # set GEMINI_API_KEY to enable LLM triage (optional)
npm run dev            # or: npm run build && npm start
```

#### LLM providers

Triage + the executive summary can run on **Gemini** or **Claude**. Each provider
is usable only when it is **enabled** AND its **API key** is present:

| Provider | Default | Env |
| --- | --- | --- |
| Gemini | **enabled** | `GEMINI_API_KEY`, `GEMINI_MODEL` (default `gemini-3.6-flash`), `GEMINI_ENABLED=true` |
| Claude | **disabled** | `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` (default `claude-sonnet-4-6`), `CLAUDE_ENABLED=false` |

The frontend model selector lists all providers; disabled ones (or ones missing a
key) are shown but not selectable. Requests may pass `provider: "gemini" | "claude"`;
an unavailable choice falls back to the default available provider. With **no**
usable provider the pipeline runs in **deterministic-only mode**: triage degrades
to a pass-through verdict and the summary is generated in code. LLM outages during
a scan also degrade gracefully rather than failing the scan.

For real repo scans, install the CLIs on PATH: `gitleaks` (**v8.19 or later**;
full-history scans use `gitleaks git`, which older versions lack), `semgrep`, `npm`.

#### Deployment and target safety

| Env | Default | Purpose |
| --- | --- | --- |
| `CORS_ORIGINS` | localhost:5173 | Browser origins allowed to read API responses |
| `TRUST_PROXY` | unset | Proxy hops to trust for client IPs (set `1` behind Render, Railway, Nginx or a load balancer, or every user shares one rate-limit bucket) |
| `REPO_HOST_ALLOWLIST` | `github.com,gitlab.com,bitbucket.org` | Hosts repo scans may clone from (https only, no credentials or ports) |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow targets resolving to private, loopback or link-local IPs (local fixtures only) |
| `REPORT_TTL_MS` / `REPORT_MAX` | 24h / 500 | In-memory report retention |
| `SEMGREP_CONFIG` | `p/security-audit,p/owasp-top-ten` + language packs | Semgrep rulesets, comma-separated; point at a local rules file or folder for offline/air-gapped runners. Scanner-X's own rules (`backend/rules/scanner-x.yml`) always run too |
| `SCANNER_X_CUSTOM_RULES` | `1` | Set to `0` to skip Scanner-X's own semgrep rules |
| `SCANNER_X_EPSS_THRESHOLD` | `0.01` | High/critical dependency advisories with an EPSS exploit probability below this are lowered one level |
| `SCANNER_X_OFFLINE` | unset | Set to `1` to skip the CISA KEV / EPSS lookups |

Domain and repo targets are resolved before scanning and refused if any address
is private, loopback, link-local or reserved. Domain-mode HTTP and TLS connections
re-check the resolved address at connect time, so DNS rebinding can't bypass this.
Git clones are restricted to https with redirects disabled.

To scan the local fixtures (`npm run serve:exposed-fixture`, `npm run serve:csp-fixtures`),
start the backend with `ALLOW_PRIVATE_TARGETS=true` and scan `127.0.0.1:4174` or
`127.0.0.1:4175`. With the flag on, domain mode accepts `localhost` or an IPv4
address with an optional port, scanned over plain http, and the server logs a
startup warning. IP literals are otherwise refused at connect time.

### Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173, proxies /api → :4000
                       # API_TARGET=http://localhost:4001 npm run dev  → another backend
```

## API

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| POST | `/api/scan/repo` | `{ repoUrl, checks?: string[] \| "all", provider?, failOn?, triage?, fullHistory?, baseRef?, headRef? }` | `{ reportId }` |
| POST | `/api/scan/domain` | `{ domain, attested: boolean, checks?, provider?, failOn?, triage? }` (403 unless `attested === true`) | `{ reportId }` |
| GET | `/api/report/:reportId` | — | assembled report |
| GET | `/api/checks` | — | available checks per mode |
| GET | `/api/models` | — | LLM providers (id, model, enabled, available) |

Both scan routes also have `/stream` variants that return server-sent progress events.

### Diff (PR) scans

Pass `baseRef` (the PR's base branch or commit) and optionally `headRef` (the PR
head: a branch, commit SHA, or a PR ref such as `refs/pull/N/head` (GitHub) or
`refs/merge-requests/N/head` (GitLab) for fork PRs; defaults to the
repo's default branch). The repo is cloned, diffed with `git diff base...head`,
and only findings in changed files are reported. The report shows how many files
changed, and a base that resolves to the same commit as the head is refused with a
clear error instead of producing an empty report. Dependency findings are kept
when any `package.json` or lockfile changed, including nested workspace
manifests. Gitleaks always scans the commits in `base..head`, so a secret added
and then removed within the PR is still reported. The other tools still run over
the whole checkout, so diff scans save report noise and LLM cost, not tool runtime.

### Private repositories

Public repos clone anonymously. There are two ways to scan a private repo:

1. **Per scan, from the web UI**: tick **Private repository** under the repo URL and
   paste a read-only access token (GitHub, Bitbucket, GitLab or Azure DevOps; for
   Bitbucket you can also set the username). The token is sent with that one scan
   request as `accessToken` (and optional `tokenUsername`), used only for the repo's
   host, kept in memory for the clone and scan, and never stored, logged or put in
   the report. It takes precedence over a server token for the same host.
2. **Server-wide, in `backend/.env`**: a **read-only** token per git host, as below.

Never put a token in `.env.example` or the repo URL; URLs with credentials are rejected.

| Host | Token and minimum permission | Variable |
| --- | --- | --- |
| GitHub | Fine-grained PAT, *Contents: Read-only* | `GITHUB_TOKEN`, `GITHUB_OWNERS` |
| GitLab (cloud or self-hosted) | Personal/group/project access token, `read_repository` | `GITLAB_TOKEN`, `GITLAB_OWNERS`, `GITLAB_HOST` |
| Bitbucket Cloud | API token or repository access token with repository read | `BITBUCKET_TOKEN`, `BITBUCKET_USERNAME`, `BITBUCKET_OWNERS` |
| Azure DevOps | PAT with *Code: Read* | `AZURE_DEVOPS_TOKEN`, `AZURE_DEVOPS_OWNERS` |
| Anything else (Gitea, Bitbucket Server, more hosts) | Token with repo read | `GIT_CREDENTIALS` (JSON) |

`*_OWNERS` lists the users, orgs or groups (the first path segment of the repo URL)
a token may be used for, and is **required**: a token without owners is ignored (and
logged at startup), so a `GITHUB_TOKEN` exported in your shell for other tools is
never used by accident. Set it to `*` to allow any owner; the server then warns that
anyone who can reach the API can scan every repo the token can read. For Bitbucket, check Atlassian's current docs for the username that
goes with your token type (`x-bitbucket-api-token-auth` for API tokens, the default,
or `x-token-auth` for access tokens).

```bash
GITHUB_TOKEN=github_pat_...
GITHUB_OWNERS=adarshm07

# Several hosts, or a self-hosted server, in one variable (keep it on one line):
GIT_CREDENTIALS=[{"host":"gitlab.mycompany.com","username":"oauth2","token":"glpat-...","owners":["platform"]}]
REPO_HOST_ALLOWLIST=github.com,gitlab.com,bitbucket.org,dev.azure.com,gitlab.mycompany.com
REPO_PRIVATE_HOSTS=gitlab.mycompany.com   # only if it resolves to an internal IP
```

How tokens are handled:

- Sent to git as an HTTP `Authorization` header scoped to that one host, through
  `GIT_CONFIG_*` environment variables, so they never appear in the process list,
  the clone URL, error messages or reports (errors are also redacted).
- Git credential helpers are disabled for scans (`credential.helper=`), so the
  scanner never falls back to a login saved on the server (such as the macOS
  Keychain), and git never prompts (`GIT_TERMINAL_PROMPT=0`).
- In CI (GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines) the repo is
  already checked out, so no token is needed there.

## CLI

Scan a local checkout without the web server (local dev, CI, coding agents):

```bash
cd backend && npm ci && npm run build
node dist/cli.js --path ../some-repo --fail-on high --sarif out.sarif --json out.json
node dist/cli.js --path . --base origin/main      # only changes since origin/main
node dist/cli.js --path . --html site/index.html  # self-contained HTML report
node dist/cli.js --help
```

Exit codes: `0` policy passed, `1` policy failed or scan incomplete, `2` usage
error. In diff mode the base must exist in the local history, and a base equal to
`HEAD` is refused (there is nothing to compare). LLM triage is off unless you pass
`--triage gemini|claude|openai`, because it sends code snippets to the provider.

Verdicts from another reviewer, such as the coding agent running the skill, can be
merged into a saved report with the same effect as the built-in triage (false
positives removed, severities adjusted, policy recomputed):

```bash
node dist/cli.js apply-triage --report scan.json --triage verdicts.json --sarif out.sarif
```

**Secrets are masked before any AI call.** Values found by gitleaks are replaced
(e.g. `sk_l****`) in every snippet, message and metadata field before triage, so they
never reach the model or its gateway logs, and never appear in the saved report, JSON
or SARIF.

`--sarif` writes SARIF 2.1.0, which GitHub code scanning and most code-review tools
import. Each result carries a stable fingerprint, a `security-severity` score, and
the triage explanation and fix when triage ran.

## GitHub Action

Runs on pull requests, annotates the diff through code scanning, and fails the
check when findings reach `fail-on`:

```yaml
# .github/workflows/scanner-x.yml
name: Scanner-X
on: pull_request
permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning
  pull-requests: write     # summary comment on each PR
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # diff mode needs the PR base commit
      - uses: adarshm07/scanner@main
        with:
          fail-on: high      # critical | high | medium | low
          # checks: secrets,sast,deps
          # diff-only: "true"   # only report files the PR changes
          # triage: gemini      # optional; needs GEMINI_API_KEY in env
          # report-url: https://<you>.github.io/<repo>/   # linked from the PR comment
```

The action installs gitleaks and semgrep if they aren't on the runner, builds the
CLI, writes a job summary, uploads `scanner-x.sarif`, posts one summary comment on the
PR (updated on each push, listing only the problems the PR introduces), and then
enforces the policy.
On `pull_request` it scans only the PR's changes (secrets in every PR commit); on
other events it scans the whole repo. Inputs reach the scripts through environment
variables, never inline, so they can't inject shell commands. Linux runners only.

### Publish the report to GitHub Pages

Set `html-file` and deploy the folder with the standard Pages actions. The page is
self-contained, has secrets masked, and links each finding to the scanned commit. Live
example: [scanner-x-demo](https://github.com/adarshm07/scanner-x-demo), with its
[workflow](https://github.com/adarshm07/scanner-x-demo/blob/main/.github/workflows/scanner-x.yml).

```yaml
      - uses: adarshm07/scanner@main
        with:
          html-file: site/index.html
      - uses: actions/upload-pages-artifact@v3
        if: always()
        with:
          path: site
```

## Agent skill (Claude Code, Codex)

[`skills/scanner-x/SKILL.md`](skills/scanner-x/SKILL.md) lets a coding agent run
Scanner-X on the project you have open: it picks the scope (whole repo, or just
the branch's changes), runs the CLI, reads the JSON report, triages each finding
by reading the code around it, and helps fix them, then re-scans to verify. The
agent does the triage itself, so no API key is needed and no code is sent to a
second model.

Install:

```bash
git clone --depth 1 https://github.com/adarshm07/scanner ~/.scanner-x \
  && (cd ~/.scanner-x/backend && npm ci && npm run build) \
  && bash ~/.scanner-x/skills/scanner-x/scripts/setup.sh \
  && mkdir -p ~/.claude/skills ~/.codex/skills \
  && ln -sfn ~/.scanner-x/skills/scanner-x ~/.claude/skills/scanner-x \
  && ln -sfn ~/.scanner-x/skills/scanner-x ~/.codex/skills/scanner-x
```

`setup.sh` installs gitleaks, semgrep and osv-scanner if they're missing: with
Homebrew when available, otherwise semgrep via pipx/pip and the other two as
official release binaries (gitleaks checksum-verified) in `~/.scanner-x/bin`, which
Scanner-X finds automatically. It never uses sudo; `setup.sh --check` only reports.
On Windows, use WSL.

Or install just the skill with the [skills](https://www.npmjs.com/package/skills)
CLI: `npx skills add adarshm07/scanner -g -a claude-code -a codex`. On first use
the skill offers to clone and build Scanner-X and to run `setup.sh`.

Update later with `cd ~/.scanner-x && git pull && (cd backend && npm ci && npm run build)`.

Then ask "run a security scan" or use `/scanner-x`. Set `SCANNER_X_HOME` if you
cloned somewhere other than `~/.scanner-x`. If your Codex version doesn't load
skills from that folder, add a line to the project's `AGENTS.md`:
`For security scans, follow ~/.scanner-x/skills/scanner-x/SKILL.md.`

## Access review (AccessLens, Okta)

The **Access review** pages in the web app's sidebar (Dashboard, Users, Apps, Findings, Scheduled scans) cover the Okta access right-sizing idea from the AccessLens PRD. It currently runs on synthetic data from `backend/data/accesslens/` (a MongoDB export of a fake `acme-demo.okta.com` tenant: 99 users, 23 apps, 638 assignments). It does not connect to Okta yet.

- **Computed, not looked up**: Okta has no roles or findings, so AccessLens works them out from what Okta does provide (user profile and status, app assignments, admin roles, SSO sign-ins) plus our policy config. Users are grouped into cohorts by department and team; users with no department are placed in the cohort whose apps they most resemble. The eight rules (stale account, never used, unused, direct grant, outlier, missing, privileged role, separation-of-duties conflict) run in [`accesslens/engine.ts`](backend/src/accesslens/engine.ts), and the tests check them against the seed's answer key (`expected_findings.json`, all 71 matched with the same scores).
- **User list**: everyone in the tenant, sorted by risk, with filters for flagged, inactive and no-title users.
- **Per user**: title, department, team, inferred cohort (role), manager, groups and Okta admin roles. For every app: the app role, whether it was granted by group or directly, assignment and sync status, assigned date, last SSO, 90-day sign-in count, how many people in the cohort have it, and any rule flags (unused, never used, outlier, direct grant, stale account, SoD conflict, privileged role).
- **Role check**: `POST /api/accesslens/users/:id/review` asks the selected model whether the user's role needs each app (**keep / review / revoke**, with a reason and confidence) and whether to **grant** apps most of the cohort has. The rules-only verdict is kept alongside, and the UI shows where the AI disagrees with it. With no model configured, or if the model call fails, the rules verdicts are used.
- **Privacy**: the model gets role, app and usage data only. No names, emails or Okta IDs are sent.
- **Recommendations only**: nothing is written back to Okta.
- **Dashboard** (`/#dashboard`): headline counts (flagged users, new joiners, unused access, privileged users), access issues by type, users not using each app for 30/60/90+ days, team and app-sensitivity breakdowns, and lists of the riskiest users, unused sensitive access, SoD conflicts and contractors with sensitive apps. Filters for team, department, status, type and app apply across Dashboard, Apps and Findings.
- **Scheduled scans** (`/#scans`): re-checks every user daily, weekly, or on a custom cron schedule (at most hourly), or on demand. Each scan reloads the data, recomputes the findings, runs the role check for all users (or only flagged ones) with the chosen model, diffs the findings against the previous scan (new / resolved), and has the model write a short summary with next steps. The summary prompt is pseudonymous too. Schedule, history (last 60 scans) and the latest reviews are kept in `ACCESSLENS_STATE_DIR` (default `backend/.accesslens-state/`, git-ignored), so reviews survive a restart. The schedule runs inside the backend process, so it only fires while the backend is up.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/accesslens/summary` | Tenant, counts, rule totals, app catalogue |
| `GET /api/accesslens/users` | User list with app counts, risk and latest review tally |
| `GET /api/accesslens/users/:id` | Full access detail for one user |
| `POST /api/accesslens/users/:id/review` | Body `{ "provider": "openai" \| "gemini" \| "claude" \| "rules", "force": true }` |
| `GET /api/accesslens/dashboard` | Users, assignments and findings in one payload for the dashboard |
| `GET` / `PUT /api/accesslens/schedule` | Scan schedule: `{ enabled, frequency: "daily" \| "weekly" \| "custom", time, weekday, cron, timezone, provider, scope: "all" \| "flagged" }` |
| `POST /api/accesslens/scans` | Start a scan now (`{ provider?, scope? }`); 409 if one is running |
| `GET /api/accesslens/scans`, `/scans/:id` | Scan history; one scan with new / resolved findings and summary |

Set `ACCESSLENS_DATA_DIR` to point at a different export. `backend/data/accesslens/import.sh` loads the same files into MongoDB.

## Non-goals (hackathon scope)

- No active scanning (port scans, injection probes) — passive checks only.
- No DNS-based domain ownership verification — self-attestation checkbox only.
- No accounts/auth — session-based report IDs.
- CLI and Action cover repo mode only; domain scans run through the web app/API.
- No plugin loader — the tool integrations are hardcoded; the schema is designed
  so plugins are possible later.

## Add any skill using this prompt
Add a new tool adapter to Scanner-X for [CHECK NAME].

It belongs in backend/src/tools/[checkName].ts and must:

1. Run [WHAT THE CHECK ACTUALLY DOES — API call(s), command, or lookup]
2. Transform its raw output into the existing Finding schema
   (backend/src/schema/finding.ts) — do not deviate from that shape.
   - category: "[frontend|backend|cloud|architecture|domain]"
   - skill: "[unique-skill-id]"
   - Set severity/confidence yourself based on what the check found —
     don't leave that to the LLM triage step.
3. If the check can also PASS (not just find issues), emit a passing
   record too, consistent with how the domain "Checks" table already
   shows both findings and passes with observed values — don't only
   emit output when something's wrong.
4. Register it in runPipeline.ts under the appropriate scope, and add it
   to the scope-selector UI's per-check list with a cost/time estimate
   like the other checks.
5. It must be passive/read-only only, consistent with the existing
   authorization-gate design — do not add anything that performs active
   probing beyond what's already permitted for domain mode.
6. Add a fixture case for it under the test fixture repo/domain so it's
   demoable on demand (see the fixture setup from earlier).

Do not touch the triage.ts prompt template, the report assembly, or any
other tool adapter while doing this — this should be a fully isolated
addition.
