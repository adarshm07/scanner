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
| domain | TLS / cert (+ SSL Labs) | [`tools/tlsCheck.ts`](backend/src/tools/tlsCheck.ts) |
| domain | HTTP security headers | [`tools/headerCheck.ts`](backend/src/tools/headerCheck.ts) |
| domain | DNS (SPF/DKIM/DMARC) | [`tools/dnsCheck.ts`](backend/src/tools/dnsCheck.ts) |
| domain | CT subdomains (crt.sh) | [`tools/subdomainCheck.ts`](backend/src/tools/subdomainCheck.ts) |

Each adapter exposes `toolNameAdapter(rawOutput): Finding[]`, isolating all
tool-specific parsing. Repo tools fall back to demo findings when the CLI isn't
installed, so the pipeline stays demoable in any environment.

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

For real repo scans, install the CLIs on PATH: `gitleaks`, `semgrep`, `npm`.

### Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173, proxies /api → :4000
```

## API

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| POST | `/api/scan/repo` | `{ repoUrl, scope: string[] \| "all", provider? }` | `{ reportId }` |
| POST | `/api/scan/domain` | `{ domain, attested: boolean, provider? }` (403 unless `attested === true`) | `{ reportId }` |
| GET | `/api/report/:reportId` | — | assembled report |
| GET | `/api/skills` | — | available scope categories |
| GET | `/api/models` | — | LLM providers (id, model, enabled, available) |

## Agent skill

[`backend/src/skill/scanner-x.skill.md`](backend/src/skill/scanner-x.skill.md) —
install into a coding agent. On `/scanner-x` it asks for scope, calls the
orchestrator, and renders a severity-grouped report. On PR triggers it defaults
to scanning the diff only and posts the report as a PR comment.

## Non-goals (hackathon scope)

- No active scanning (port scans, injection probes) — passive checks only.
- No DNS-based domain ownership verification — self-attestation checkbox only.
- No accounts/auth — session-based report IDs.
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
