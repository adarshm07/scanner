# Scanner-X

AI-assisted security review that composes **deterministic, open-source scanning
tools** with a **thin LLM triage layer**. Two entry points share one backend:

1. **PR / Agent Skill** (`/scanner-x`) — interactive, scope-driven scans for repos and PRs.
2. **Domain Recon Web App** — passive security report for a domain (TLS, headers, DNS, CT subdomains).

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
| repo | npm audit (deps) | [`tools/npmAudit.ts`](backend/src/tools/npmAudit.ts) |
| domain | TLS / cert chain (+ SSL Labs) | [`tools/tlsCheck.ts`](backend/src/tools/tlsCheck.ts) |
| domain | HTTP security headers | [`tools/headerCheck.ts`](backend/src/tools/headerCheck.ts) |
| domain | DNS (SPF/DKIM/DMARC) | [`tools/dnsCheck.ts`](backend/src/tools/dnsCheck.ts) |
| domain | CT subdomains (crt.sh) | [`tools/subdomainCheck.ts`](backend/src/tools/subdomainCheck.ts) |

Each adapter exposes `toolNameAdapter(rawOutput): Finding[]`, isolating all
tool-specific parsing. A repo tool whose CLI isn't installed contributes no
findings. If the clone fails or the repo has no scannable code, the report has
zero findings, a warning, and a failed policy (`reason: "scan incomplete"`).

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
| `SEMGREP_CONFIG` | `p/security-audit` | Semgrep rules; point at a local rules file for offline/air-gapped runners |

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

Public repos clone anonymously. To scan private repos, give the backend a
**read-only** token per git host in `backend/.env` (never in `.env.example` or the
repo URL; URLs with credentials are rejected).

| Host | Token and minimum permission | Variable |
| --- | --- | --- |
| GitHub | Fine-grained PAT, *Contents: Read-only* | `GITHUB_TOKEN`, `GITHUB_OWNERS` |
| GitLab (cloud or self-hosted) | Personal/group/project access token, `read_repository` | `GITLAB_TOKEN`, `GITLAB_OWNERS`, `GITLAB_HOST` |
| Bitbucket Cloud | API token or repository access token with repository read | `BITBUCKET_TOKEN`, `BITBUCKET_USERNAME`, `BITBUCKET_OWNERS` |
| Azure DevOps | PAT with *Code: Read* | `AZURE_DEVOPS_TOKEN`, `AZURE_DEVOPS_OWNERS` |
| Anything else (Gitea, Bitbucket Server, more hosts) | Token with repo read | `GIT_CREDENTIALS` (JSON) |

`*_OWNERS` lists the users, orgs or groups (the first path segment of the repo URL)
a token may be used for. Set it: anyone who can reach the API can scan every repo
the token can read, and the server warns at startup when a token has no owner
restriction. For Bitbucket, check Atlassian's current docs for the username that
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
```

The action installs gitleaks and semgrep if they aren't on the runner, builds the
CLI, writes a job summary, uploads `scanner-x.sarif`, and then enforces the policy.
On `pull_request` it scans only the PR's changes (secrets in every PR commit); on
other events it scans the whole repo. Inputs reach the scripts through environment
variables, never inline, so they can't inject shell commands. Linux runners only.

## Agent skill (Claude Code, Codex)

[`skills/scanner-x/SKILL.md`](skills/scanner-x/SKILL.md) lets a coding agent run
Scanner-X on the project you have open: it picks the scope (whole repo, or just
the branch's changes), runs the CLI, reads the JSON report, triages each finding
by reading the code around it, and helps fix them, then re-scans to verify. The
agent does the triage itself, so no API key is needed and no code is sent to a
second model.

Install:

```bash
git clone https://github.com/adarshm07/scanner ~/.scanner-x
(cd ~/.scanner-x/backend && npm ci && npm run build)
brew install gitleaks semgrep            # or your platform's equivalent

# Claude Code: all projects (or copy into <project>/.claude/skills/ for one)
mkdir -p ~/.claude/skills && cp -r ~/.scanner-x/skills/scanner-x ~/.claude/skills/

# Codex
mkdir -p ~/.codex/skills && cp -r ~/.scanner-x/skills/scanner-x ~/.codex/skills/
```

Then ask "run a security scan" or use `/scanner-x`. Set `SCANNER_X_HOME` if you
cloned somewhere other than `~/.scanner-x`. If your Codex version doesn't load
skills from that folder, add a line to the project's `AGENTS.md`:
`For security scans, follow ~/.scanner-x/skills/scanner-x/SKILL.md.`

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
