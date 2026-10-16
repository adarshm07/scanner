import { useState } from "react";
import { CopyBlock } from "./CopyBlock";

const REPO = "adarshm07/scanner";

const SKILL_INSTALL = `npx skills add ${REPO} -g -a claude-code -a codex`;
const SKILL_UPDATE = `npx skills update scanner-x -g -y`;
const SKILL_PROMPTS = [
  "Run a Scanner-X security scan on this repo",
  "Scan this branch's changes with Scanner-X",
  "Fix the high-severity findings",
].join("\n");

const WORKFLOW = `name: Scanner-X
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # findings appear on the PR diff

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # needed to diff the PR against its base
      - uses: ${REPO}@main
        with:
          fail-on: high`;

const CLI_SETUP = `git clone https://github.com/${REPO} ~/.scanner-x
cd ~/.scanner-x/backend && npm ci && npm run build
bash ~/.scanner-x/skills/scanner-x/scripts/setup.sh   # gitleaks, semgrep, osv-scanner`;

const CLI_RUN = `# whole repo
node ~/.scanner-x/backend/dist/cli.js --path .

# only this branch's changes, like a PR check
node ~/.scanner-x/backend/dist/cli.js --path . --base origin/main

# SARIF for code scanning / IDEs
node ~/.scanner-x/backend/dist/cli.js --path . --sarif scanner-x.sarif`;

type Tab = "agent" | "pr" | "cli";

const TABS: { id: Tab; label: string }[] = [
  { id: "agent", label: "Claude Code / Codex" },
  { id: "pr", label: "Pull requests" },
  { id: "cli", label: "Terminal" },
];

function Steps({ children }: { children: React.ReactNode }) {
  return <ol className="m-0 flex list-none flex-col gap-5 p-0">{children}</ol>;
}

function Step({ n, title, note, children }: { n: number; title: string; note?: string; children?: React.ReactNode }) {
  return (
    <li className="grid grid-cols-[24px_minmax(0,1fr)] gap-3">
      <span className="font-mono text-[12px] leading-[20px] text-dim">{n}</span>
      <div className="flex min-w-0 flex-col gap-2">
        <span className="text-[13.5px] font-medium leading-[20px] text-ink3">{title}</span>
        {note && <span className="text-[12.5px] leading-normal text-muted">{note}</span>}
        {children}
      </div>
    </li>
  );
}

/** How to run Scanner-X outside this page: agent skill, GitHub PR check, local CLI. */
export function WorkflowPanel() {
  const [tab, setTab] = useState<Tab>("agent");

  return (
    <section aria-labelledby="workflow-heading" className="mt-14 border-t border-line pt-8">
      <div className="mb-5 flex flex-col gap-1">
        <h2 id="workflow-heading" className="m-0 text-[18px] font-semibold tracking-[-0.01em]">
          Use it where you work
        </h2>
        <p className="m-0 text-[13px] text-muted">
          The same scanners run in your coding agent, on every pull request, or from your terminal.
        </p>
      </div>

      <div role="tablist" aria-label="Ways to run Scanner-X" className="mb-6 inline-flex w-fit max-w-full flex-wrap gap-1 rounded border border-edge p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`cursor-pointer rounded border-0 px-3 py-1.5 text-[13px] ${
              tab === t.id ? "bg-panel2 text-ink3" : "bg-transparent text-muted hover:text-text3"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" className="max-w-[820px]">
        {tab === "agent" && (
          <Steps>
            <Step n={1} title="Install the skill" note="Needs Node. Works in any repo; nothing to clone first.">
              <CopyBlock label="Terminal" text={SKILL_INSTALL} />
            </Step>
            <Step
              n={2}
              title="Ask your agent"
              note="It installs the scanners on first use (asks first), runs them, then triages each finding itself — no API key, and no code goes to a second model."
            >
              <CopyBlock label="Example prompts" text={SKILL_PROMPTS} copyText="Run a Scanner-X security scan on this repo" />
            </Step>
            <Step n={3} title="Update later">
              <CopyBlock label="Terminal" text={SKILL_UPDATE} />
            </Step>
          </Steps>
        )}

        {tab === "pr" && (
          <Steps>
            <Step n={1} title="Add the workflow" note="Save as .github/workflows/scanner-x.yml in the repo you want checked.">
              <CopyBlock label=".github/workflows/scanner-x.yml" text={WORKFLOW} />
            </Step>
            <Step
              n={2}
              title="Open a pull request"
              note="Only files the PR changes are reported (secrets are checked in every PR commit). Findings show on the changed lines, the run summary lists them, and the check fails at high or above — or if a scanner couldn't run."
            />
            <Step
              n={3}
              title="Block merging (optional)"
              note="Settings → Branches → add a rule for main → require the Scanner-X check. Private repos need GitHub Advanced Security for inline findings; set upload-sarif: &quot;false&quot; to keep just the pass/fail check."
            />
          </Steps>
        )}

        {tab === "cli" && (
          <Steps>
            <Step n={1} title="Set up once">
              <CopyBlock label="Terminal" text={CLI_SETUP} />
            </Step>
            <Step
              n={2}
              title="Scan from your repo"
              note="Exit code 0 = passed, 1 = findings at or above --fail-on (default high) or an incomplete scan, 2 = usage error."
            >
              <CopyBlock label="Terminal" text={CLI_RUN} />
            </Step>
          </Steps>
        )}
      </div>
    </section>
  );
}
