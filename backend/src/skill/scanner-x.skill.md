---
name: scanner-x
description: >
  AI-assisted security review. Invoked as /scanner-x. Runs deterministic,
  open-source security tools (gitleaks, semgrep, npm audit for repos; TLS,
  header, DNS, and certificate-transparency checks for domains), reduces their
  output to a small structured JSON payload, and uses an LLM only to triage,
  prioritize, and explain the findings. Use when the user asks to run a security
  review, scan a repo or PR for vulnerabilities, or audit a domain's exposure.
license: MIT
---

# Scanner-X

Scanner-X composes deterministic security tools with a thin LLM triage layer.
**The deterministic tools do all detection.** The LLM only triages,
prioritizes, explains, and writes the summary — never raw code analysis at scale.

## Configuration

- `SCANNER_X_API` — base URL of the orchestrator API (default `http://localhost:4000`).
- The orchestrator handles all tool execution and LLM calls; this skill is a thin
  client that scopes the run and formats the report.

## Behavior

### 1. On invocation (`/scanner-x`)

Ask the user to choose a scope:

> **What should I scan?**
> 1. **Full pipeline** — all applicable checks
> 2. **One category** — `frontend`, `backend`, `cloud`, or `architecture` (repo) / `domain` (recon)
> 3. **A specific check** — e.g. just secrets, just TLS

Map the answer to a `scope`:
- Full pipeline → `"all"`
- One category → `["backend"]` (etc.)
- Specific check → the narrowest matching category

### 2. Repo mode

Call the orchestrator:

```
POST {SCANNER_X_API}/api/scan/repo
{ "repoUrl": "<repo url>", "scope": ["backend"] | "all" }
→ { "reportId": "..." }
```

Then fetch the report:

```
GET {SCANNER_X_API}/api/report/{reportId}
```

### 3. Domain mode (passive recon only)

Before scanning a domain, confirm authorization with the user
("Do you own or are you authorized to test this domain?"). Only proceed on an
explicit yes, and pass `attested: true`:

```
POST {SCANNER_X_API}/api/scan/domain
{ "domain": "example.com", "attested": true }
→ { "reportId": "..." }
```

Never run active scans (port scans, injection probes). Passive checks only.

### 4. PR trigger (when wired via CI)

- Default to scanning **the diff only**: restrict findings to files changed in the
  PR rather than the whole repo, to keep compute and LLM cost down.
- Post the final report as a **PR comment**:
  - Executive summary at the top.
  - Findings grouped by severity.
  - Each finding collapsed (`<details>`) with explanation, suggested fix, and snippet.

## Report format

Render the report returned by `GET /api/report/{reportId}` like this:

```markdown
## 🛡️ Scanner-X Report — <target>

<executive summary>

**Totals:** N findings (X critical · Y high · Z medium · W low)

### 🔴 Critical
<details><summary><title> — <file:line></summary>

- **Verdict:** <true_positive|needs_review>
- **Why:** <explanation>
- **Fix:** <suggested_fix>

```<snippet>```
</details>

### 🟠 High
...
```

Group by severity (critical → high → medium → low) across all categories. Omit
empty severity sections. Do not surface findings the triage step marked as
`false_positive`.

## Guardrails

- Never invent findings; only report what the deterministic tools produced.
- Never weaken or skip the domain attestation gate.
- Keep the raw finding payload small — the orchestrator already hydrates only the
  ~20-line snippet around each surviving finding.
