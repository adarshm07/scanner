import { useEffect, useMemo, useState } from "react";
import type { Check, ProviderDescriptor, ProviderId, Report, ScanEvent } from "./types";
import { DomainInput } from "./components/DomainInput";
import { ScopeSelector } from "./components/ScopeSelector";
import { ModelSelector } from "./components/ModelSelector";
import { JobPanel } from "./components/JobPanel";
import { ScanProgress } from "./components/ScanProgress";
import { ReportView } from "./components/ReportView";
import { WorkflowPanel } from "./components/WorkflowPanel";
import { streamScan } from "./lib/scanStream";

type Mode = "repo" | "domain";

export default function App() {
  const [mode, setMode] = useState<Mode>("repo");
  const [checks, setChecks] = useState<Check[]>([]);
  const [providers, setProviders] = useState<ProviderDescriptor[]>([]);
  const [providerId, setProviderId] = useState<ProviderId | null>(null);
  // Each mode keeps its own target, so switching to Domain doesn't carry a repo URL over.
  const [targets, setTargets] = useState<Record<Mode, string>>({ repo: "", domain: "" });
  const target = targets[mode];
  const setTarget = (value: string) => setTargets((t) => ({ ...t, [mode]: value }));
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [attested, setAttested] = useState(false);
  const [failOn, setFailOn] = useState("high");
  const [triage, setTriage] = useState(true);
  const [fullHistory, setFullHistory] = useState(false);
  const [baseRef, setBaseRef] = useState("");
  const [headRef, setHeadRef] = useState("");
  // Private repo token: kept in memory only, sent with this scan, never stored or shown in commands.
  const [isPrivate, setIsPrivate] = useState(false);
  const [accessToken, setAccessToken] = useState("");
  const [tokenUsername, setTokenUsername] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);

  useEffect(() => {
    fetch("/api/checks")
      .then((r) => r.json())
      .then((d) => setChecks(d.checks ?? []))
      .catch(() => setChecks([]));
    fetch("/api/models")
      .then((r) => r.json())
      .then((d) => {
        const list: ProviderDescriptor[] = d.providers ?? [];
        setProviders(list);
        const def =
          list.find((p) => p.isDefault && p.available) ??
          list.find((p) => p.available);
        setProviderId(def?.id ?? null);
      })
      .catch(() => setProviders([]));
  }, []);

  const modeChecks = useMemo(
    () => checks.filter((c) => c.mode === mode),
    [checks, mode]
  );

  // Default every check for the current mode to on (design behavior); re-runs
  // when the mode changes or the catalog first loads.
  useEffect(() => {
    setSelected(new Set(modeChecks.map((c) => c.id)));
  }, [modeChecks]);

  const toggle = (id: string) => {
    if (id === "secrets" && selected.has(id)) setFullHistory(false);
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // Parallel-run estimate: slowest selected check + triage overhead (design).
  const estimate = useMemo(() => {
    const chosen = modeChecks.filter((c) => selected.has(c.id));
    if (chosen.length === 0) return "";
    const secs = chosen.reduce((m, c) => {
      const n = parseInt(c.est.replace(/[^\d]/g, ""), 10);
      return Math.max(m, Number.isFinite(n) ? n : 0);
    }, 0);
    const total = secs + (triage && providerId ? 8 : 0);
    const label = chosen.length === 1 ? "1 check" : `${chosen.length} checks, in parallel`;
    return `${label}, about ${total}s`;
  }, [modeChecks, selected, triage, providerId]);

  const canSubmit =
    target.trim().length > 0 &&
    selected.size > 0 &&
    (mode === "repo" || attested) &&
    (mode !== "repo" || !isPrivate || accessToken.trim().length > 0) &&
    !loading;

  const repoHost = useMemo(() => {
    try {
      return new URL(targets.repo.trim()).hostname.toLowerCase();
    } catch {
      return "";
    }
  }, [targets.repo]);

  const tokenHint =
    repoHost === "bitbucket.org"
      ? "Bitbucket: a repository access token (username x-token-auth) or an Atlassian API token with repository read scope."
      : repoHost === "gitlab.com" || repoHost.includes("gitlab")
        ? "GitLab: a personal or project access token with read_repository scope."
        : repoHost === "dev.azure.com"
          ? "Azure DevOps: a personal access token with Code (Read) scope."
          : "GitHub: a fine-grained token with Contents: Read-only for this repo (or a classic token with repo scope).";

  async function runScan() {
    setLoading(true);
    setError(null);
    setReport(null);
    setScanEvents([]);
    try {
      const chosen = modeChecks
        .map((c) => c.id)
        .filter((id) => selected.has(id));
      const endpoint =
        mode === "repo" ? "/api/scan/repo/stream" : "/api/scan/domain/stream";
      const body =
        mode === "repo"
          ? {
              repoUrl: target.trim(),
              checks: chosen,
              provider: providerId ?? undefined,
              failOn,
              triage,
              fullHistory,
              baseRef: baseRef.trim() || undefined,
              headRef: (baseRef.trim() && headRef.trim()) || undefined,
              ...(isPrivate && accessToken.trim()
                ? {
                    accessToken: accessToken.trim(),
                    tokenUsername: (repoHost === "bitbucket.org" && tokenUsername.trim()) || undefined,
                  }
                : {}),
            }
          : { domain: target.trim(), attested, checks: chosen, provider: providerId ?? undefined, failOn, triage };

      let reportId: string | null = null;

      await streamScan(endpoint, body, (e) => {
        setScanEvents((prev) => [...prev, e]);
        if (e.t === "done") reportId = e.reportId;
      });

      if (!reportId) throw new Error("Scan ended without a report.");

      const reportRes = await fetch(`/api/report/${reportId}`);
      const reportData = await reportRes.json();
      if (!reportRes.ok) throw new Error(reportData.error ?? "Report fetch failed");
      setReport(reportData);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  // After a scan, the report becomes a full-width page of its own (design).
  if (report) {
    return (
      <div className="min-h-screen bg-ink text-ink3">
        <div className="mx-auto w-full max-w-[1400px] px-6 py-8">
          <ReportView report={report} onNewScan={() => setReport(null)} />
        </div>
      </div>
    );
  }

  // While a scan runs, show the live streaming progress screen (design).
  if (loading && scanEvents.length > 0) {
    return (
      <div className="min-h-screen bg-ink text-ink3">
        <div className="mx-auto w-full max-w-[1400px] px-6 py-8">
          <ScanProgress events={scanEvents} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-ink text-ink3">
      <header className="flex h-[52px] items-center gap-3 border-b border-line px-6">
        <span className="text-[15px] font-semibold tracking-[-0.01em]">Scanner-X</span>
        <span className="text-[13px] text-muted">
          Deterministic security tools + thin LLM triage
        </span>
        <div className="grow" />
        <span className="hidden font-mono text-[12px] text-dim sm:block">
          {providerId ? `triage: ${providerId}` : "triage: deterministic"}
        </span>
      </header>

      <main className="mx-auto w-full max-w-[1200px] px-6 py-10">
        <div className="mb-8">
          <h1 className="m-0 text-[26px] font-semibold tracking-[-0.02em]">New scan</h1>
        </div>
        <div className="grid grid-cols-[minmax(0,1fr)] gap-12 lg:grid-cols-[minmax(0,1fr)_380px] lg:items-start">
          {/* left: numbered sections */}
          <div className="flex flex-col">
            {/* 01 Target */}
            <section className="grid grid-cols-[32px_minmax(0,1fr)] gap-4 border-t border-line py-7">
              <span className="font-mono text-[13px] text-dim">01</span>
              <div className="flex flex-col gap-4">
                <h2 className="m-0 text-[15px] font-semibold">Target</h2>
                <div className="inline-flex w-fit gap-1 rounded border border-edge p-1">
                  {(["repo", "domain"] as Mode[]).map((m) => {
                    const active = mode === m;
                    return (
                      <button
                        key={m}
                        onClick={() => {
                          setMode(m);
                          setReport(null);
                        }}
                        aria-pressed={active}
                        className={`rounded-[3px] px-3 py-1 text-[13px] font-medium transition-colors ${
                          active ? "bg-ink3 text-ink" : "text-text3 hover:bg-hover"
                        }`}
                      >
                        {m === "repo" ? "Repository" : "Domain"}
                      </button>
                    );
                  })}
                </div>
                <DomainInput mode={mode} value={target} onChange={setTarget} />
                {mode === "repo" && (
                  <div className="flex flex-col gap-3">
                    <label className="flex cursor-pointer items-start gap-2.5 text-[13px] text-text3">
                      <input
                        type="checkbox"
                        className="mt-0.5 h-4 w-4 accent-ink3"
                        checked={isPrivate}
                        onChange={(e) => {
                          setIsPrivate(e.target.checked);
                          if (!e.target.checked) {
                            setAccessToken("");
                            setTokenUsername("");
                          }
                        }}
                      />
                      <span className="flex flex-col gap-0.5">
                        <span>Private repository</span>
                        <span className="text-[12px] text-muted">
                          Clone with an access token for GitHub, Bitbucket, GitLab or Azure DevOps.
                        </span>
                      </span>
                    </label>
                    {isPrivate && (
                      <div className="ml-[26px] flex flex-col gap-1.5 text-[13px] text-text3">
                        <label htmlFor="access-token" className="font-medium text-muted">
                          Access token
                        </label>
                        <input
                          id="access-token"
                          type="password"
                          value={accessToken}
                          onChange={(e) => setAccessToken(e.target.value)}
                          placeholder="paste a read-only token"
                          autoComplete="off"
                          spellCheck={false}
                          className="h-[34px] w-full rounded border border-edge bg-ink2 px-2 font-mono text-[13px] text-ink3 outline-hidden placeholder:text-[#9ca3af] focus:border-muted"
                        />
                        {repoHost === "bitbucket.org" && (
                          <input
                            value={tokenUsername}
                            onChange={(e) => setTokenUsername(e.target.value)}
                            placeholder="username (optional, default x-bitbucket-api-token-auth)"
                            autoComplete="off"
                            spellCheck={false}
                            className="h-[34px] w-full rounded border border-edge bg-ink2 px-2 font-mono text-[13px] text-ink3 outline-hidden placeholder:text-[#9ca3af] focus:border-muted"
                          />
                        )}
                        <span className="text-[12px] text-muted">{tokenHint}</span>
                        <span className="text-[12px] text-muted">
                          Used only to clone this repo for this scan. Never stored, logged or included in the report.
                        </span>
                      </div>
                    )}
                  </div>
                )}
                {mode === "repo" && (
                  <label className="flex cursor-pointer items-start gap-2.5 text-[13px] text-text3">
                    <input
                      type="checkbox"
                      className="mt-0.5 h-4 w-4 accent-ink3"
                      checked={fullHistory}
                      disabled={!selected.has("secrets")}
                      onChange={(e) => setFullHistory(e.target.checked)}
                    />
                    <span className="flex flex-col gap-0.5">
                      <span>Scan full Git history</span>
                      <span className="text-[12px] text-muted">
                        {selected.has("secrets")
                          ? "Gitleaks checks every commit. Fetching full history can take much longer."
                          : "Select the Secrets check to enable history scanning."}
                      </span>
                    </span>
                  </label>
                )}
                {mode === "repo" && (
                  <div className="flex flex-col gap-1.5 text-[13px] text-text3">
                    <span>Scan only changes (optional)</span>
                    <div className="flex gap-2">
                      <input
                        value={baseRef}
                        onChange={(e) => setBaseRef(e.target.value)}
                        placeholder="base branch, e.g. main"
                        className="h-[34px] min-w-0 flex-1 rounded border border-edge bg-ink2 px-2 font-mono text-[13px] text-ink3 outline-hidden placeholder:text-[#9ca3af] focus:border-muted"
                      />
                      <input
                        value={headRef}
                        onChange={(e) => setHeadRef(e.target.value)}
                        disabled={!baseRef.trim()}
                        placeholder="head: branch, SHA or PR/MR ref"
                        className="h-[34px] min-w-0 flex-1 rounded border border-edge bg-ink2 px-2 font-mono text-[13px] text-ink3 outline-hidden placeholder:text-[#9ca3af] focus:border-muted disabled:opacity-50"
                      />
                    </div>
                    <span className="text-[12px] text-muted">
                      Reports only findings in files changed between base and head, like a PR check.
                    </span>
                  </div>
                )}
                {mode === "domain" && (
                  <label className="flex cursor-pointer items-start gap-2.5 rounded border border-edge bg-panel/40 p-3 text-[13px] text-text3">
                    <input
                      type="checkbox"
                      className="mt-0.5 h-4 w-4 accent-ink3"
                      checked={attested}
                      onChange={(e) => setAttested(e.target.checked)}
                    />
                    <span className="flex flex-col gap-0.5">
                      <span>I own this host or have written permission to test it.</span>
                      <span className="text-[12px] text-muted">
                        Required for domain scans. Your confirmation is stored with the scan record.
                      </span>
                    </span>
                  </label>
                )}
              </div>
            </section>

            {/* 02 Checks */}
            <section className="grid grid-cols-[32px_minmax(0,1fr)] gap-4 border-t border-line py-7">
              <span className="font-mono text-[13px] text-dim">02</span>
              <div className="flex flex-col gap-4">
                <ScopeSelector checks={modeChecks} selected={selected} onToggle={toggle} />
                <ModelSelector providers={providers} value={providerId} onChange={setProviderId} />
              </div>
            </section>

            {/* 03 Policy */}
            <section className="grid grid-cols-[32px_minmax(0,1fr)] gap-4 border-y border-line py-7">
              <span className="font-mono text-[13px] text-dim">03</span>
              <div className="flex flex-col gap-4">
                <h2 className="m-0 text-[15px] font-semibold">Policy</h2>
                <label className="flex items-center gap-2.5 text-[13px] text-text3">
                  <span>Fail the check at</span>
                  <select
                    value={failOn}
                    onChange={(e) => setFailOn(e.target.value)}
                    className="h-[34px] rounded border border-edge bg-ink2 px-2 text-[13px] text-ink3 outline-hidden placeholder:text-[#9ca3af] focus:border-muted"
                  >
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                  </select>
                  <span className="text-muted">and above</span>
                </label>
                <label className="flex cursor-pointer items-start gap-2.5 text-[13px] text-text3">
                  <input
                    type="checkbox"
                    className="mt-0.5 h-4 w-4 accent-ink3"
                    checked={triage}
                    onChange={(e) => setTriage(e.target.checked)}
                  />
                  <span className="flex flex-col gap-0.5">
                    <span>Explain and triage findings with the model</span>
                    <span className="text-[12px] text-muted">
                      {triage
                        ? providerId
                          ? `Sends each finding's rule, location and up to 20 lines of context to ${providerId}. Severities stay as the scanners report them.`
                          : "No model available — runs deterministic triage. Severities stay as the scanners report them."
                        : "Off. Severities and messages come straight from the scanners."}
                    </span>
                  </span>
                </label>
              </div>
            </section>
          </div>

          {/* right: job panel */}
          <JobPanel
            mode={mode}
            target={target}
            attested={attested}
            checks={modeChecks}
            selected={selected}
            failOn={failOn}
            triage={triage}
            fullHistory={fullHistory}
            baseRef={baseRef.trim()}
            headRef={headRef.trim()}
            providerId={providerId}
            estimate={estimate}
            canSubmit={canSubmit}
            loading={loading}
            onRun={runScan}
            error={error}
          />
        </div>

        <WorkflowPanel />
      </main>
    </div>
  );
}
