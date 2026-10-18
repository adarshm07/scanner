---
name: scanner-x
description: Run a Scanner-X security scan (secrets, code/SAST, vulnerable dependencies in JavaScript, Python, Java, Rust, Go and more) on the current repository or just its branch changes, then explain and fix the findings. Use when the user asks for a security scan, security review or audit of their code, a branch or a PR, or mentions Scanner-X.
---

# Scanner-X security scan

Scanner-X runs deterministic tools (gitleaks for secrets, semgrep for code patterns,
npm audit for dependencies) and reports structured findings. **You are the triage
layer**: the tools do all detection; you read the code around each finding, decide
whether it is real, explain it and help fix it. Never invent findings the tools did not
report.

## 1. Find the CLI

The CLI lives in the Scanner-X repository at `backend/dist/cli.js`.

1. Use `$SCANNER_X_HOME` if it is set; otherwise try `~/.scanner-x`.
2. If neither exists, ask the user where Scanner-X is checked out, or offer to run
   `git clone https://github.com/adarshm07/scanner ~/.scanner-x`.
3. If `backend/dist/cli.js` is missing or older than the sources, build it:
   `cd "$SCANNER_X_HOME/backend" && npm ci && npm run build`.
4. Check the scanners with the setup script that ships with this skill (in this skill's
   `scripts/` folder, or `$SCANNER_X_HOME/skills/scanner-x/scripts/`):
   `bash <skill dir>/scripts/setup.sh --check`.
   If anything is missing, ask the user once: "Install gitleaks, semgrep and osv-scanner
   now? (Homebrew if available, otherwise user-level installs into ~/.scanner-x/bin; no
   sudo)". On yes, run `bash <skill dir>/scripts/setup.sh`. On no, continue: the report
   will mark the missing checks as not scanned.
   - gitleaks: secrets. semgrep: code patterns. osv-scanner: dependencies for Python,
     Java, Rust, Go, Ruby, PHP, .NET and yarn/pnpm (npm projects use npm audit).
   - On Windows, run Scanner-X inside WSL.

## 2. Choose the scope

- If the user named a scope (whole repo, a branch, a PR, specific checks), use it.
- Otherwise: on the default branch, scan the whole repo. On any other branch, ask once:
  "Scan only this branch's changes, or the whole repo?" For branch changes, use the merge
  base as the base: `git merge-base HEAD origin/<default-branch>`.
- Checks: `secrets`, `sast`, `deps` (default: all).
- **A repository URL instead of the current folder**: clone it into a temporary
  directory (`git clone <url> "$(mktemp -d)/repo"`; the user's own git credentials apply
  to private repos) and scan that path. Delete the clone afterwards, and don't offer
  to edit files there; offer fixes only for a repo the user has checked out.
- **Changes between two refs** ("from main to feature/x"): fetch both, check out the head
  (`git checkout <head>`) and pass the base as `--base`. If only a base is given, scan the
  current HEAD against it.
- **Severity threshold** ("fail on medium and above"): pass `--fail-on <severity>`
  (default `high`).
- **Full history** ("including git history"): pass `--full-history` (secrets only).

## 3. Run it

```bash
OUT="${TMPDIR:-/tmp}/scanner-x-$(date +%s).json"
node "$SCANNER_X_HOME/backend/dist/cli.js" \
  --path "<repo root, or the temporary clone>" \
  [--base <ref>] [--checks secrets,sast,deps] [--full-history] [--fail-on high] \
  --json "$OUT" --quiet
```

- Exit code 1 only means the policy failed (findings at or above `--fail-on`, or an
  incomplete scan). It is not an error; read the JSON. Exit code 2 is a usage error.
- Do **not** pass `--triage`: you do the triage, so no code leaves the machine for a
  second model.
- Dependency scans may take a minute when a manifest has no lockfile (the scanner
  resolves versions in a temporary directory; the repo is not modified).

## 4. Read the report

The JSON is a Scanner-X report. Key fields:

- `policy.passed`, `policy.reason`, `policy.countAtOrAbove`
- `warning`: what was **not** scanned and why. If present, or `policy.reason` is
  `"scan incomplete"`, say so first. Never describe an incomplete scan as clean.
- `diff`: `{ baseRef, changedFiles }` for branch scans
- `stats.bySeverity` and `categories[].findings[]`, each with `severity`, `confidence`,
  `title`, `location` (`file`, `line_start`), `tool_message`, `rule_id`, `raw_snippet`
  and `metadata` (`cwe`, `advisoryUrl`, `fixAvailable`, `lockfileGenerated`, ...)

## 5. Triage each finding

Open the file at `location` and read enough surrounding code to judge it. Decide
**real**, **likely false positive** (say exactly which line or fact shows it), or
**needs review**.

- **gitleaks-\***: real unless the value is clearly a placeholder, a published example
  key, or in a test/fixture/example path. Do not downgrade because a key "might be
  rotated" — you can't know that.
- **semgrep-\***: real when the flagged input is attacker-controlled at that call site
  (request params, body, headers, file contents from users). A value built only from
  constants or server config is not the same risk.
- **npm-audit-\*** and **osv-\*** (the `dependencies` category, any language): the
  vulnerable package is really installed, so never mark one `false_positive`. Your job is
  **reachability**: can this app reach the vulnerable code? `metadata.usage` shows where
  the app loads the package (or the direct dependency in `metadata.pulledInBy` that
  pulls it in): `status` is `imported`, `referenced` (string or package.json script),
  `not_found` or `unsupported`, and `sites` gives `file:line` with context. Open those
  files and read the advisory, then set `reachability`:
  - `reachable`: the app plausibly hits the vulnerable function or feature (e.g. it parses
    request data with it, serves HTTP with that framework, renders with that template engine).
  - `not_reachable`: you can name why not (the advisory needs an API, option or mode the
    app never uses; it's only used by a CLI/build step; nothing loads it). Say which.
  - `unknown`: the evidence doesn't settle it. Prefer this to guessing; transitive packages
    of a framework are usually `unknown` unless the advisory names a path the app exercises.
  Scanner-X enforces the effect: `not_reachable` drops to low (medium if KEV) and stops
  failing the policy, `reachable` keeps at least the scanner's severity, `unknown` can go
  at most one level lower. Nothing is removed.
  Already applied by the scanner: `metadata.devOnly` (capped at low), `metadata.kev`
  (CISA Known Exploited, raised to critical: fix first), `metadata.epss` /
  `metadata.loweredByEpss`, and `metadata.loweredByUsage` (never loaded, lowered one level).
  If `metadata.lockfileGenerated` is true, the installed versions may differ. For the fix,
  use `metadata.fixedVersions`, upgrade `metadata.pulledInBy` for transitive packages, and
  name the manifest (`metadata.ecosystem`: npm, PyPI, Maven, crates.io, Go, ...).

## 6. Report to the user

1. One line: scope, number of findings by severity, and policy result (plus any
   `warning`).
2. Code and secret findings first, grouped by severity, most severe first. Then
   dependencies grouped by reachability (reachable, unconfirmed, not reachable, not
   loaded, dev only), so vulnerable packages never bury the code issues. For each: title, `file:line`, your
   verdict, why it matters here (one or two sentences), and the concrete fix.
3. Skip findings you judged false positives in the main list; mention them briefly at
   the end with the reason.

**Never print a secret's full value.** Show at most the first 4 characters followed by `…`.
The report already masks detected secrets (e.g. `sk_l****`), but you may see the real value
when you open the file yourself.

## 6b. Save your triage into the report

Write your verdicts so the report files carry them, exactly like Scanner-X's built-in AI
triage would (false positives removed, severities adjusted, policy recomputed). Do this
after every triaged scan; it's how your analysis reaches the JSON, SARIF (GitHub code
scanning) and anyone the user shares the report with.

```bash
cat > "${TMPDIR:-/tmp}/scanner-x-verdicts.json" <<'JSON'
[
  {
    "finding_id": "<id from the report>",
    "verdict": "true_positive",
    "adjusted_severity": "high",
    "explanation": "Why it matters here, naming the file and line.",
    "suggested_fix": "The concrete change or command."
  },
  {
    "finding_id": "<id of a dependency finding>",
    "verdict": "true_positive",
    "reachability": "not_reachable",
    "explanation": "marked's ReDoS is in the markdown parser; the app imports marked only in scripts/build-docs.js, never on a request path.",
    "suggested_fix": "1. npm install marked@4.0.10\n2. Re-run the scan to confirm."
  }
]
JSON
node "$SCANNER_X_HOME/backend/dist/cli.js" apply-triage \
  --report "$OUT" --triage "${TMPDIR:-/tmp}/scanner-x-verdicts.json" --quiet
```

Fields: `verdict` is `true_positive`, `false_positive` or `needs_review`;
`adjusted_severity` (optional) is `critical`, `high`, `medium` or `low`; `reachability`
(dependency findings) is `reachable`, `not_reachable` or `unknown`; `explanation` is
required; `suggested_fix` is optional. Add `--sarif scanner-x.sarif --path <repo root>`
when the user wants a SARIF file. Use the exact `finding_id`
values from the report. Never put a secret's value in a verdict. The command prints
any entries it ignored; fix and re-run if needed. Mention the output paths to the user, and
only write files inside their repo (such as the SARIF) if they ask for them.

## 7. Fix (only with the user's go-ahead)

Offer to fix; ask before editing files.

- **Leaked secret**: tell the user to **revoke/rotate it first** (removing it from code
  does not un-leak it), then move it to an environment variable or secret store. It stays
  in git history; mention history rewriting only if the repo is private and not yet shared.
- **Code finding**: make the minimal change at the flagged line (parameterized queries,
  output encoding, input validation, safer API) and keep behavior otherwise unchanged.
- **Dependency**: upgrade to the fixed version (`npm install <pkg>@<version>` in the
  manifest's directory, or `npm audit fix`), then run the project's tests.

After fixing, re-run the same scan (same scope and checks) and report what changed.
Do not commit or push unless the user asks.

## Guardrails

- Report only what the tools found; don't add findings of your own to the scan results
  (you may mention other concerns separately, clearly labeled).
- Don't disable rules, delete tests, or add ignores just to make the policy pass.
- Domain scans (TLS, headers, DNS) are not part of the CLI. They need the Scanner-X web
  API and an explicit confirmation that the user owns or may test the domain.
