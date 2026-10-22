import { useEffect, useMemo, useState } from "react";
import type { ProviderDescriptor, ProviderId } from "../types";
import { ModelSelector } from "../components/ModelSelector";
import { SeverityGlyph } from "../components/Severity";
import type { AccessVerdict, AlSummary, AlUserDetail, AlUserSummary, UserReview } from "./types";

/**
 * AccessLens: Okta users, the apps each one holds, how the access was granted and used,
 * and an AI verdict on whether the user's role needs it. Data is the synthetic tenant
 * under backend/data/accesslens.
 */

const VERDICT_STYLE: Record<AccessVerdict | "grant" | "skip", string> = {
  keep: "border-[#2f6b52] bg-[#2f6b52]/20 text-[#7fd1a8]",
  review: "border-[#7a6420] bg-[#7a6420]/20 text-[#e8c45a]",
  revoke: "border-[#8a2f40] bg-[#8a2f40]/25 text-[#f58aa0]",
  grant: "border-[#2d5a85] bg-[#2d5a85]/25 text-[#8cc1f0]",
  skip: "border-edge bg-panel text-muted",
};

const RULE_LABEL: Record<string, string> = {
  STALE_ACCOUNT: "Stale account",
  UNUSED_ACCESS: "Unused",
  NEVER_USED: "Never used",
  OUTLIER_ACCESS: "Outlier",
  MISSING_ACCESS: "Missing",
  DIRECT_ASSIGNMENT: "Direct grant",
  PRIVILEGED_ROLE: "Privileged role",
  TOXIC_COMBINATION: "SoD conflict",
};

function Pill({ kind, children }: { kind: keyof typeof VERDICT_STYLE; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-[3px] border px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide ${VERDICT_STYLE[kind]}`}>
      {children}
    </span>
  );
}

function Tag({ children, tone = "plain" }: { children: React.ReactNode; tone?: "plain" | "warn" }) {
  return (
    <span
      className={`inline-flex items-center rounded-[3px] border px-1.5 py-0.5 text-[11px] ${
        tone === "warn" ? "border-[#7a6420] text-[#e8c45a]" : "border-edge text-text3"
      }`}
    >
      {children}
    </span>
  );
}

function ago(days: number | null): string {
  if (days == null) return "never";
  if (days === 0) return "today";
  if (days < 60) return `${days}d ago`;
  return `${Math.round(days / 30)}mo ago`;
}

function pct(n: number | null): string {
  return n == null ? "—" : `${Math.round(n * 100)}%`;
}

function roleText(u: AlUserSummary): string {
  return u.title ?? (u.cohort ? `${u.cohort.label} (inferred)` : "Unknown role");
}

type Filter = "all" | "flagged" | "inactive" | "no-title";

export function AccessLensView({ userId = null }: { userId?: number | null }) {
  const [summary, setSummary] = useState<AlSummary | null>(null);
  const [users, setUsers] = useState<AlUserSummary[]>([]);
  const [providers, setProviders] = useState<ProviderDescriptor[]>([]);
  const [providerId, setProviderId] = useState<ProviderId | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [selectedId, setSelectedIdState] = useState<number | null>(userId);
  // Keep the open user in the URL (#users/<id>) so dashboard links land on them.
  useEffect(() => setSelectedIdState(userId), [userId]);
  const setSelectedId = (id: number) => {
    setSelectedIdState(id);
    window.history.replaceState(null, "", `#users/${id}`);
  };
  const [detail, setDetail] = useState<AlUserDetail | null>(null);
  const [review, setReview] = useState<UserReview | null>(null);
  const [reviewing, setReviewing] = useState(false);
  const [githubScanning, setGithubScanning] = useState(false);
  const [githubScanResult, setGithubScanResult] = useState<{
    reportId?: string;
    repoUrl?: string;
    message?: string;
    report?: {
      executiveSummary?: string;
      stats?: { totalAfterFilter?: number; bySeverity?: Record<string, number> };
      categories?: Array<{ category: string; findings: Array<{ title: string; severity: string; rule_id?: string }> }>;
    };
  } | null>(null);
  const [reportViewer, setReportViewer] = useState<{ open: boolean; data: Record<string, unknown> | null }>({
    open: false,
    data: null,
  });
  const [error, setError] = useState<string | null>(null);

  const refreshUsers = () =>
    fetch("/api/accesslens/users")
      .then((r) => r.json())
      .then((d) => setUsers(d.users ?? []));

  useEffect(() => {
    fetch("/api/accesslens/summary")
      .then((r) => r.json())
      .then(setSummary)
      .catch(() => setError("Backend not reachable. Start it with `npm run dev` in backend/."));
    refreshUsers().catch(() => undefined);
    fetch("/api/models")
      .then((r) => r.json())
      .then((d) => {
        const list: ProviderDescriptor[] = d.providers ?? [];
        setProviders(list);
        setProviderId((list.find((p) => p.isDefault && p.available) ?? list.find((p) => p.available))?.id ?? null);
      })
      .catch(() => setProviders([]));
  }, []);

  useEffect(() => {
    if (selectedId == null) return;
    setDetail(null);
    setReview(null);
    setError(null);
    fetch(`/api/accesslens/users/${selectedId}`)
      .then((r) => r.json())
      .then((d) => {
        setDetail(d.user);
        setReview(d.review);
      })
      .catch((e) => setError((e as Error).message));
  }, [selectedId]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const hasSearch = q.length > 0;
    return users
      .filter((u) => {
        if (!hasSearch && filter === "flagged" && u.findingCount === 0) return false;
        if (!hasSearch && filter === "inactive" && u.status === "ACTIVE") return false;
        if (!hasSearch && filter === "no-title" && u.title) return false;
        if (!hasSearch) return true;
        return [u.name, u.email, u.title, u.department, u.team, u.cohort?.label]
          .filter(Boolean)
          .some((s) => s!.toLowerCase().includes(q));
      })
      .sort((a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name));
  }, [users, query, filter]);

  async function runReview(force: boolean) {
    if (!detail) return;
    setReviewing(true);
    setError(null);
    try {
      const res = await fetch(`/api/accesslens/users/${detail.id}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: providerId ?? "rules", force }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Review failed");
      setReview(data.review);
      refreshUsers().catch(() => undefined);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setReviewing(false);
    }
  }

  async function runGithubScan() {
    if (!detail?.github?.repoUrl) return;
    setGithubScanning(true);
    setGithubScanResult(null);
    setReportViewer({ open: false, data: null });
    setError(null);
    try {
      const res = await fetch(`/api/accesslens/users/${detail.id}/scan-github`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: detail.github.repoUrl }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "GitHub scan failed");
      setGithubScanResult({
        reportId: data.reportId,
        repoUrl: data.repoUrl,
        message: `Repo scan complete for ${data.repoUrl}`,
        report: data.report,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setGithubScanning(false);
    }
  }

  async function openFullReport(reportId: string | undefined) {
    if (!reportId) return;
    setError(null);
    try {
      const res = await fetch(`/api/report/${encodeURIComponent(reportId)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to load report");
      setReportViewer({ open: true, data });
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const decisionFor = (appKey: string) => review?.decisions.find((d) => d.appKey === appKey);
  const missingFor = (appKey: string) => review?.missing.find((m) => m.appKey === appKey);
  const githubTopFindings =
    githubScanResult?.report?.categories?.flatMap((category) =>
      (category.findings ?? []).map((finding) => ({
        category: category.category,
        title: finding.title,
        severity: finding.severity,
      }))
    )?.slice(0, 3) ?? [];
  const githubSeverity = githubScanResult?.report?.stats?.bySeverity ?? { critical: 0, high: 0, medium: 0, low: 0 };

  return (
    <div>
      <main className="mx-auto w-full max-w-[1400px] px-6 py-8">
        <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="m-0 text-[24px] font-semibold tracking-[-0.02em]">Users</h1>
            <p className="mt-1 text-[13px] text-muted">
              Who has which apps, how they got them, whether they use them, and whether their role needs them.
              Demo data from a synthetic tenant{summary ? ` (${summary.tenant.domain})` : ""}.
            </p>
          </div>
          {summary && (
            <div className="flex flex-wrap gap-6 font-mono text-[12px] text-muted">
              <Stat label="users" value={summary.userCount} />
              <Stat label="apps" value={summary.appCount} />
              <Stat label="assignments" value={summary.assignmentCount} />
              <Stat label="inactive users" value={summary.userCount - (summary.statusCounts.ACTIVE ?? 0)} />
              <Stat label="flagged users" value={users.filter((u) => u.findingCount > 0).length} />
            </div>
          )}
        </div>

        {error && <div className="mb-4 rounded border border-[#8a2f40] bg-[#8a2f40]/15 px-3 py-2 text-[13px] text-[#f58aa0]">{error}</div>}

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[360px_minmax(0,1fr)]">
          {/* user list */}
          <aside className="flex flex-col rounded border border-line bg-panel/40 lg:max-h-[calc(100vh-200px)]">
            <div className="flex flex-col gap-2 border-b border-line p-3">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search name, title, team, cohort"
                className="h-[34px] rounded border border-edge bg-ink2 px-2 text-[13px] text-ink3 outline-hidden placeholder:text-dim focus:border-muted"
              />
              <div className="flex flex-wrap gap-1">
                {(
                  [
                    ["flagged", "Flagged"],
                    ["all", "All"],
                    ["inactive", "Inactive"],
                    ["no-title", "No title"],
                  ] as [Filter, string][]
                ).map(([f, label]) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    aria-pressed={filter === f}
                    className={`rounded-[3px] px-2 py-0.5 text-[12px] ${filter === f ? "bg-ink3 text-ink" : "text-text3 hover:bg-hover"}`}
                  >
                    {label}
                  </button>
                ))}
                <span className="ml-auto self-center font-mono text-[11px] text-dim">{visible.length}</span>
              </div>
            </div>
            <ul className="m-0 list-none overflow-y-auto p-0">
              {visible.map((u) => (
                <li key={u.id}>
                  <button
                    onClick={() => setSelectedId(u.id)}
                    className={`flex w-full flex-col gap-1 border-b border-line2 px-3 py-2.5 text-left hover:bg-hover ${
                      selectedId === u.id ? "bg-hover" : ""
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span className="text-[13.5px] font-medium text-ink3">{u.name}</span>
                      {u.status !== "ACTIVE" && <Pill kind="revoke">{u.status.toLowerCase()}</Pill>}
                      {u.employeeType === "Contractor" && <Tag>contractor</Tag>}
                      <span className="ml-auto font-mono text-[11px] text-dim">{u.appCount} apps</span>
                    </span>
                    <span className="text-[12px] text-muted">
                      {roleText(u)}
                      {u.department ? ` · ${u.department}` : ""}
                    </span>
                    <span className="flex flex-wrap items-center gap-1">
                      {u.topRules.slice(0, 3).map((r) => (
                        <Tag key={r} tone="warn">
                          {RULE_LABEL[r] ?? r}
                        </Tag>
                      ))}
                      {u.review && (
                        <span className="ml-auto font-mono text-[11px] text-dim">
                          {u.review.engine === "llm" ? "AI" : "rules"}: {u.review.revoke} revoke · {u.review.review} review
                        </span>
                      )}
                    </span>
                  </button>
                </li>
              ))}
              {visible.length === 0 && <li className="p-4 text-[13px] text-muted">No users match.</li>}
            </ul>
          </aside>

          {/* detail */}
          <section className="min-w-0">
            {!selectedId && (
              <div className="rounded border border-dashed border-edge p-10 text-center text-[13px] text-muted">
                Pick a user to see their apps, access type and usage, and run the AI role check.
              </div>
            )}
            {selectedId && !detail && <div className="p-6 text-[13px] text-muted">Loading…</div>}
            {detail && (
              <div className="flex flex-col gap-5">
                {/* profile */}
                <div className="rounded border border-line bg-panel/40 p-5">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="m-0 text-[20px] font-semibold">{detail.name}</h2>
                        <Pill kind={detail.status === "ACTIVE" ? "keep" : "revoke"}>{detail.status.toLowerCase()}</Pill>
                      </div>
                      <div className="mt-0.5 font-mono text-[12px] text-dim">
                        {detail.email} · {detail.oktaId}
                      </div>
                    </div>
                    <div className="flex w-full max-w-[320px] flex-col gap-2">
                      <ModelSelector providers={providers} value={providerId} onChange={setProviderId} />
                      <button
                        onClick={() => runReview(review != null)}
                        disabled={reviewing}
                        className="h-9 rounded bg-ink3 px-3 text-[13px] font-medium text-ink hover:bg-white disabled:opacity-50"
                      >
                        {reviewing ? "Checking access…" : review ? "Re-run role check" : providerId ? "Check access with AI" : "Check access (rules only)"}
                      </button>
                    </div>
                  </div>
                  <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-[13px] md:grid-cols-4">
                    <Field label="Title" value={detail.title ?? "— not set in Okta"} />
                    <Field label="Department / team" value={[detail.department, detail.team].filter(Boolean).join(" / ") || "—"} />
                    <Field
                      label="Inferred role (cohort)"
                      value={detail.cohort ? `${detail.cohort.label} · ${pct(detail.cohort.similarity)} match${detail.cohort.inferred ? " · inferred from apps (no department in Okta)" : ""}` : "—"}
                    />
                    <Field label="Manager" value={detail.manager?.name ?? "—"} />
                    <Field label="Type / country" value={`${detail.employeeType} · ${detail.country}`} />
                    <Field label="Last Okta login" value={detail.lastLogin?.slice(0, 10) ?? "never"} />
                    <Field label="Okta admin roles" value={detail.adminRoles.join(", ") || "none"} warn={detail.adminRoles.length > 0} />
                    <Field label="Groups" value={detail.groups.join(", ") || "—"} />
                  </dl>
                  {detail.userFindings.map((f) => (
                    <div key={f.id} className="mt-3 rounded border border-[#7a6420] bg-[#7a6420]/10 px-3 py-2 text-[13px] text-[#e8c45a]">
                      {RULE_LABEL[f.rule] ?? f.rule}: {f.explanation}
                      {Array.isArray(f.evidence.apps) ? ` (${(f.evidence.apps as string[]).join(" + ")})` : ""}
                    </div>
                  ))}

                  {detail.github?.repoUrl && (
                    <div className="mt-4 rounded border border-[#2d5a85] bg-[#2d5a85]/12 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <div className="text-[11px] uppercase tracking-wide text-dim">GitHub access</div>
                          <div className="mt-1 font-mono text-[12px] text-text3">{detail.github.owner}/{detail.github.repo}</div>
                        </div>
                        <button
                          onClick={runGithubScan}
                          disabled={githubScanning}
                          className="h-8 rounded bg-ink3 px-3 text-[12px] font-medium text-ink hover:bg-white disabled:opacity-50"
                        >
                          {githubScanning ? "Scanning…" : "Scan private repo"}
                        </button>
                      </div>
                      {detail.github.username && (
                        <div className="mt-2 text-[12px] text-muted">User: {detail.github.username} · PAT configured in dataset</div>
                      )}
                      {githubScanResult && (
                        <div className="mt-3 rounded border border-[#2f6b52] bg-[#2f6b52]/15 p-3 text-[12px] text-[#dbeedd]">
                          <div className="flex items-center justify-between gap-3">
                            <div className="font-medium text-[#7fd1a8]">{githubScanResult.message}</div>
                            <span className="font-mono text-[11px] text-dim">{githubScanResult.reportId ?? "generated"}</span>
                          </div>

                          {githubScanResult.report?.executiveSummary && (
                            <p className="mt-2 text-[13px] leading-relaxed text-text3">{githubScanResult.report.executiveSummary}</p>
                          )}

                          {githubScanResult.report?.stats && (
                            <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] text-muted md:grid-cols-4">
                              <StatMini label="Total" value={githubScanResult.report.stats.totalAfterFilter ?? 0} />
                              <StatMini label="Critical" value={githubSeverity.critical ?? 0} />
                              <StatMini label="High" value={githubSeverity.high ?? 0} />
                              <StatMini label="Medium" value={githubSeverity.medium ?? 0} />
                            </div>
                          )}

                          {githubTopFindings.length > 0 && (
                            <div className="mt-3">
                              <div className="mb-1 text-[11px] uppercase tracking-wide text-dim">Top findings</div>
                              <ul className="m-0 list-disc space-y-1 pl-4 text-[12px] text-text3">
                                {githubTopFindings.map((finding, index) => (
                                  <li key={`${finding.category}-${index}`}>
                                    <span className="uppercase text-dim">{finding.severity}</span> · {finding.title}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {githubScanResult.reportId && (
                            <div className="mt-3 flex flex-wrap items-center gap-2">
                              <button
                                onClick={() => {
                                  if (reportViewer.open && reportViewer.data) {
                                    setReportViewer({ open: false, data: null });
                                    return;
                                  }
                                  openFullReport(githubScanResult.reportId);
                                }}
                                className="h-8 rounded border border-[#7fd1a8] bg-transparent px-3 text-[12px] font-medium text-[#7fd1a8] hover:bg-[#7fd1a8]/10"
                              >
                                {reportViewer.open ? "Hide report" : "Open full report"}
                              </button>
                            </div>
                          )}

                          {reportViewer.open && reportViewer.data && (
                            <div className="mt-3 rounded border border-line bg-ink2 p-2">
                              <pre className="m-0 max-h-[240px] overflow-auto whitespace-pre-wrap break-words text-[11px] leading-5 text-text3">
                                {JSON.stringify(reportViewer.data, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {review && (
                  <div className="rounded border border-line bg-panel/40 p-5">
                    <div className="mb-1 flex items-center gap-2 font-mono text-[11px] uppercase tracking-wide text-dim">
                      {review.engine === "llm" ? `AI role check · ${review.provider}` : "Rules-only check"}
                      <span className="normal-case">· {new Date(review.generatedAt).toLocaleTimeString()}</span>
                    </div>
                    <p className="m-0 text-[14px] text-ink3">{review.roleAssessment}</p>
                    <p className="mt-1 text-[13px] text-muted">{review.summary}</p>
                    {review.error && <p className="mt-2 text-[12px] text-[#e8c45a]">{review.error}</p>}
                  </div>
                )}

                {/* access table */}
                <div className="overflow-x-auto rounded border border-line">
                  <table className="w-full min-w-[920px] border-collapse text-[13px]">
                    <thead>
                      <tr className="border-b border-line bg-panel text-left text-[11px] uppercase tracking-wide text-dim">
                        <th className="px-3 py-2 font-medium">App</th>
                        <th className="px-3 py-2 font-medium">Access type</th>
                        <th className="px-3 py-2 font-medium">Assigned</th>
                        <th className="px-3 py-2 font-medium">Last used</th>
                        <th className="px-3 py-2 font-medium text-right">SSO 90d</th>
                        <th className="px-3 py-2 font-medium text-right">Cohort has it</th>
                        <th className="px-3 py-2 font-medium">Flags</th>
                        <th className="px-3 py-2 font-medium">Needs it?</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.access.map((a) => {
                        const d = decisionFor(a.appKey);
                        return (
                          <tr key={a.appKey} className="border-b border-line2 align-top">
                            <td className="px-3 py-2.5">
                              <div className="flex items-center gap-2">
                                <SeverityGlyph severity={a.sensitivity} size={11} />
                                <span className="font-medium text-ink3">{a.appLabel}</span>
                              </div>
                              <div className="pl-[19px] font-mono text-[11px] text-dim">{a.sensitivity} · {a.signOnMode}</div>
                            </td>
                            <td className="px-3 py-2.5">
                              <div className="text-text3">role: {a.appRoles.join(", ") || "—"}</div>
                              <div className={`text-[12px] ${a.source === "DIRECT" ? "text-[#e8c45a]" : "text-muted"}`}>
                                {a.source === "DIRECT" ? "direct assignment" : `via ${a.viaGroup}`}
                              </div>
                              <div className="font-mono text-[11px] text-dim">{a.status.toLowerCase()} · {a.syncState.toLowerCase()}</div>
                            </td>
                            <td className="whitespace-nowrap px-3 py-2.5 text-text3">{a.assignedAt?.slice(0, 10) ?? "—"}</td>
                            <td className={`whitespace-nowrap px-3 py-2.5 ${a.daysSinceUse == null || a.daysSinceUse >= 90 ? "text-[#f58aa0]" : "text-text3"}`}>
                              {ago(a.daysSinceUse)}
                            </td>
                            <td className="px-3 py-2.5 text-right font-mono text-text3">{a.ssoCount90d}</td>
                            <td className={`px-3 py-2.5 text-right font-mono ${a.cohortShare != null && a.cohortShare < 0.1 ? "text-[#e8c45a]" : "text-text3"}`}>
                              {pct(a.cohortShare)}
                            </td>
                            <td className="px-3 py-2.5">
                              <div className="flex flex-wrap gap-1">
                                {a.findings.map((f) => (
                                  <span key={f.id} title={f.explanation}>
                                    <Tag tone="warn">{RULE_LABEL[f.rule] ?? f.rule}</Tag>
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="max-w-[300px] px-3 py-2.5">
                              {d ? (
                                <div className="flex flex-col gap-1">
                                  <span className="flex items-center gap-1.5">
                                    <Pill kind={d.verdict}>{d.verdict}</Pill>
                                    <span className="font-mono text-[11px] text-dim">{d.confidence}</span>
                                    {review?.engine === "llm" && d.verdict !== d.ruleVerdict && (
                                      <span className="font-mono text-[11px] text-dim" title="Rules alone would say this">
                                        rules: {d.ruleVerdict}
                                      </span>
                                    )}
                                  </span>
                                  <span className="text-[12px] leading-snug text-muted">{d.reason}</span>
                                </div>
                              ) : (
                                <span className="text-[12px] text-dim">not checked</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* missing access */}
                {detail.missing.length > 0 && (
                  <div className="rounded border border-line bg-panel/40 p-5">
                    <h3 className="m-0 text-[14px] font-semibold">Possibly missing access</h3>
                    <p className="mt-0.5 text-[12px] text-muted">
                      Apps most of the {detail.cohort?.label ?? "cohort"} cohort ({detail.cohortSize} active users) has that {detail.name.split(" ")[0]} doesn't.
                    </p>
                    <ul className="mt-3 flex list-none flex-col gap-2 p-0">
                      {detail.missing.map((m) => {
                        const r = missingFor(m.appKey);
                        return (
                          <li key={m.appKey} className="flex flex-wrap items-center gap-3 text-[13px]">
                            <SeverityGlyph severity={m.sensitivity} size={11} />
                            <span className="min-w-[150px] font-medium">{m.appLabel}</span>
                            <span className="font-mono text-[12px] text-muted">{pct(m.cohortShare)} of cohort</span>
                            {r && <Pill kind={r.verdict}>{r.verdict}</Pill>}
                            {r && <span className="text-[12px] text-muted">{r.reason}</span>}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}
                <p className="m-0 text-[12px] text-dim">
                  Verdicts are recommendations only; nothing is changed in Okta. The model sees role, app and usage data,
                  never names, emails or Okta IDs.
                </p>
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <span className="flex flex-col items-end">
      <span className="text-[18px] font-semibold text-ink3">{value}</span>
      <span>{label}</span>
    </span>
  );
}

function Field({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wide text-dim">{label}</dt>
      <dd className={`m-0 mt-0.5 break-words ${warn ? "text-[#e8c45a]" : "text-text3"}`}>{value}</dd>
    </div>
  );
}

function StatMini({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-line bg-ink2 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-dim">{label}</div>
      <div className="mt-1 font-mono text-[12px] text-text3">{value}</div>
    </div>
  );
}
