import { useCallback, useEffect, useRef, useState } from "react";
import type { ProviderDescriptor } from "../../types";
import { RULE_LABEL } from "./data";
import { load, remove, save as persist, savedAgo } from "../../lib/storage";
import { Chip, Empty, Panel, Table, userLink } from "./ui";

/** Mirrors backend/src/accesslens/scans.ts. */
type Frequency = "daily" | "weekly" | "custom";
interface ScanSchedule {
  enabled: boolean;
  frequency: Frequency;
  time: string;
  weekday: number;
  cron: string;
  timezone: string;
  provider: string;
  scope: "all" | "flagged";
  updatedAt: string | null;
}
interface FindingRef {
  key: string;
  userId: number;
  userName: string;
  appKey: string | null;
  appLabel: string | null;
  rule: string;
  riskScore: number;
}
interface ScanRun {
  id: string;
  trigger: "schedule" | "manual";
  status: "running" | "done" | "failed";
  startedAt: string;
  finishedAt: string | null;
  provider: string;
  scope: "all" | "flagged";
  progress: { done: number; total: number };
  usersTotal: number;
  usersReviewed: number;
  modelFallbacks: number;
  flaggedUsers: number;
  findingsTotal: number;
  byRule: Record<string, number>;
  verdicts: { keep: number; review: number; revoke: number; grant: number };
  newFindings: FindingRef[];
  resolvedFindings: FindingRef[];
  previousRunId: string | null;
  summary: { headline: string; highlights: string[]; actions: string[]; engine: "llm" | "rules" } | null;
  error?: string;
}

type SavedSchedule = { schedule: ScanSchedule; cron: string; nextRuns: string[] };
const SCHEDULE_CACHE = "cache/scan-schedule";
const RUNS_CACHE = "cache/scan-runs";
const MODELS_CACHE = "cache/models";
/** Unsaved schedule edits (a UI preference, not cached server data). */
const DRAFT_KEY = "prefs/scan-schedule-draft";

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const CRON_PRESETS: [string, string][] = [
  ["0 9 * * 1-5", "Weekdays at 09:00"],
  ["0 */6 * * *", "Every 6 hours"],
  ["0 8 1 * *", "1st of every month at 08:00"],
  ["0 8 * * 1,4", "Mon and Thu at 08:00"],
];

const input =
  "h-[34px] rounded border border-edge bg-ink2 px-2 text-[13px] text-ink3 outline-hidden focus:border-muted disabled:opacity-50";

function when(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function duration(r: ScanRun) {
  if (!r.finishedAt) return "";
  const s = Math.round((new Date(r.finishedAt).getTime() - new Date(r.startedAt).getTime()) / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

function modelName(id: string, providers: ProviderDescriptor[]) {
  if (id === "rules") return "Rules only";
  const p = providers.find((x) => x.id === id);
  return p ? `${p.label}` : id;
}

export function ScansPage({ onScanFinished }: { onScanFinished: () => void }) {
  // Start from the browser's copy, then refresh from the backend.
  const [saved, setSaved] = useState<SavedSchedule | null>(() => load<SavedSchedule>(SCHEDULE_CACHE)?.value ?? null);
  const [draft, setDraftState] = useState<ScanSchedule | null>(
    () => load<ScanSchedule>(DRAFT_KEY)?.value ?? load<SavedSchedule>(SCHEDULE_CACHE)?.value.schedule ?? null
  );
  const [providers, setProviders] = useState<ProviderDescriptor[]>(() => load<ProviderDescriptor[]>(MODELS_CACHE)?.value ?? []);
  const [runs, setRuns] = useState<ScanRun[]>(() => load<ScanRun[]>(RUNS_CACHE)?.value ?? []);
  const [offlineSince, setOfflineSince] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const wasRunning = useRef(false);

  const loadRuns = useCallback(
    () =>
      fetch("/api/accesslens/scans")
        .then((r) => r.json())
        .then((d) => {
          const list: ScanRun[] = d.runs ?? [];
          setRuns(list);
          persist(RUNS_CACHE, list);
          setOfflineSince(null);
          const running = list.some((r) => r.status === "running");
          if (wasRunning.current && !running) onScanFinished();
          wasRunning.current = running;
        }),
    [onScanFinished]
  );

  useEffect(() => {
    fetch("/api/accesslens/schedule")
      .then((r) => r.json())
      .then((d) => {
        // A schedule never saved defaults to the viewer's own time zone.
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        setSaved(d);
        persist(SCHEDULE_CACHE, d);
        // Unsaved edits made in this browser win over the server copy.
        const pending = load<ScanSchedule>(DRAFT_KEY)?.value;
        setDraftState(pending ?? (d.schedule.updatedAt ? d.schedule : { ...d.schedule, timezone: tz }));
      })
      .catch(() => {
        const cachedAt = load<SavedSchedule>(SCHEDULE_CACHE)?.savedAt;
        if (cachedAt) setOfflineSince(cachedAt);
        else setError("Backend not reachable. Start it with `npm run dev` in backend/.");
      });
    fetch("/api/models")
      .then((r) => r.json())
      .then((d) => {
        setProviders(d.providers ?? []);
        persist(MODELS_CACHE, d.providers ?? []);
      })
      .catch(() => undefined);
    loadRuns().catch(() => undefined);
  }, [loadRuns]);

  const running = runs.find((r) => r.status === "running");
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => loadRuns().catch(() => undefined), 1500);
    return () => clearInterval(t);
  }, [running, loadRuns]);

  const dirty = !!(saved && draft && JSON.stringify({ ...saved.schedule, updatedAt: null }) !== JSON.stringify({ ...draft, updatedAt: null }));
  const setDraft = (d: ScanSchedule | null, keep: boolean) => {
    setDraftState(d);
    if (keep && d) persist(DRAFT_KEY, d);
    else remove(DRAFT_KEY);
  };
  const set = <K extends keyof ScanSchedule>(k: K, v: ScanSchedule[K]) => draft && setDraft({ ...draft, [k]: v }, true);

  async function save(next = draft) {
    if (!next) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch("/api/accesslens/schedule", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(next),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error ?? "Could not save the schedule");
      setSaved(d);
      persist(SCHEDULE_CACHE, d);
      setDraft(d.schedule, false);
      setNotice(d.schedule.enabled ? "Schedule saved." : "Schedule saved. Scheduled scans are off.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function runNow() {
    if (!draft) return;
    setError(null);
    setNotice(null);
    const res = await fetch("/api/accesslens/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: draft.provider, scope: draft.scope }),
    });
    const d = await res.json();
    if (!res.ok) setError(d.error ?? "Could not start the scan");
    else {
      wasRunning.current = true;
      setOpenId(d.run.id);
    }
    loadRuns().catch(() => undefined);
  }

  const latest = runs.find((r) => r.status === "done");
  const open = runs.find((r) => r.id === openId) ?? null;

  if (!draft) {
    return error ? <ErrorBox>{error}</ErrorBox> : <div className="text-[13px] text-muted">Loading…</div>;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="m-0 text-[24px] font-semibold tracking-[-0.02em]">Scheduled scans</h1>
          <p className="m-0 mt-1 max-w-[720px] text-[13px] text-muted">
            Re-check every user's access on a schedule. Each scan refreshes the Okta data, recomputes the findings, runs the AI role
            check on each user, and reports what changed since the last scan.
          </p>
        </div>
        <button
          onClick={runNow}
          disabled={!!running}
          className="h-9 rounded bg-ink3 px-4 text-[13px] font-medium text-ink hover:bg-white disabled:opacity-50"
        >
          {running ? `Scanning… ${running.progress.done}/${running.progress.total || "…"}` : "Run scan now"}
        </button>
      </div>

      {error && <ErrorBox>{error}</ErrorBox>}
      {offlineSince && (
        <div className="rounded border border-[#7a6420] bg-[#7a6420]/12 px-3 py-2 text-[13px] text-[#e8c45a]">
          Backend not reachable. Showing the schedule and history saved in this browser {savedAgo(offlineSince)}. Changes and new scans need the backend.
        </div>
      )}
      {dirty && !offlineSince && <div className="text-[12px] text-dim">Unsaved changes are kept in this browser until you save or discard them.</div>}
      {notice && <div className="rounded border border-[#2f6b52] bg-[#2f6b52]/15 px-3 py-2 text-[13px] text-[#7fd1a8]">{notice}</div>}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        {/* schedule */}
        <Panel
          title="Schedule"
          subtitle={
            saved?.schedule.enabled && saved.nextRuns.length
              ? `On · next scan ${when(saved.nextRuns[0])}`
              : "Off · scans only run when you start one"
          }
          action={
            <label className="flex cursor-pointer items-center gap-2 text-[13px] text-text3">
              <input
                type="checkbox"
                className="h-4 w-4 accent-[#3987e5]"
                checked={draft.enabled}
                onChange={(e) => set("enabled", e.target.checked)}
              />
              Enabled
            </label>
          }
        >
          <div className="flex flex-col gap-5">
            <Field label="How often" group>
              <div className="inline-flex w-fit gap-1 rounded border border-edge p-1">
                {(["daily", "weekly", "custom"] as Frequency[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => set("frequency", f)}
                    aria-pressed={draft.frequency === f}
                    className={`rounded-[3px] px-3 py-1 text-[13px] font-medium capitalize ${
                      draft.frequency === f ? "bg-ink3 text-ink" : "text-text3 hover:bg-hover"
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </Field>

            {draft.frequency !== "custom" ? (
              <div className="flex flex-wrap gap-4">
                {draft.frequency === "weekly" && (
                  <Field label="Day">
                    <select value={draft.weekday} onChange={(e) => set("weekday", Number(e.target.value))} className={`${input} min-w-[150px]`}>
                      {WEEKDAYS.map((d, i) => (
                        <option key={d} value={i}>
                          {d}
                        </option>
                      ))}
                    </select>
                  </Field>
                )}
                <Field label="Time">
                  <input type="time" value={draft.time} onChange={(e) => set("time", e.target.value)} className={`${input} w-[130px] [color-scheme:dark]`} />
                </Field>
                <Field label="Time zone">
                  <input value={draft.timezone} onChange={(e) => set("timezone", e.target.value)} className={`${input} w-[200px] font-mono`} spellCheck={false} />
                </Field>
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap gap-4">
                  <Field label="Cron expression">
                    <input
                      value={draft.cron}
                      onChange={(e) => set("cron", e.target.value)}
                      placeholder="minute hour day month weekday"
                      className={`${input} w-[220px] font-mono`}
                      spellCheck={false}
                    />
                  </Field>
                  <Field label="Time zone">
                    <input value={draft.timezone} onChange={(e) => set("timezone", e.target.value)} className={`${input} w-[200px] font-mono`} spellCheck={false} />
                  </Field>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {CRON_PRESETS.map(([c, label]) => (
                    <button key={c} onClick={() => set("cron", c)} className="rounded-[3px] border border-edge px-2 py-0.5 text-[12px] text-text3 hover:bg-hover">
                      {label}
                    </button>
                  ))}
                </div>
                <span className="text-[12px] text-muted">Five fields: minute, hour, day of month, month, day of week. At most once an hour.</span>
              </div>
            )}

            <div className="flex flex-wrap gap-4">
              <Field label="AI model">
                <select value={draft.provider} onChange={(e) => set("provider", e.target.value)} className={`${input} min-w-[200px]`}>
                  <option value="rules">Rules only (no model)</option>
                  {providers.map((p) => (
                    <option key={p.id} value={p.id} disabled={!p.available}>
                      {p.label} ({p.model}){p.available ? "" : " — not configured"}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Users to check">
                <select value={draft.scope} onChange={(e) => set("scope", e.target.value as ScanSchedule["scope"])} className={`${input} min-w-[200px]`}>
                  <option value="all">All users</option>
                  <option value="flagged">Only users with findings</option>
                </select>
              </Field>
            </div>
            {draft.provider !== "rules" && draft.scope === "all" && (
              <p className="m-0 text-[12px] text-muted">One model call per user. The model sees role, app and usage data, never names, emails or Okta IDs.</p>
            )}

            <div className="flex flex-wrap items-center gap-3 border-t border-line2 pt-4">
              <button
                onClick={() => save()}
                disabled={!dirty || saving}
                className="h-9 rounded bg-ink3 px-4 text-[13px] font-medium text-ink hover:bg-white disabled:opacity-40"
              >
                {saving ? "Saving…" : "Save schedule"}
              </button>
              {dirty && (
                <button onClick={() => saved && setDraft(saved.schedule, false)} className="h-9 rounded px-3 text-[13px] text-muted hover:bg-hover hover:text-ink3">
                  Discard changes
                </button>
              )}
              {saved && !dirty && saved.schedule.enabled && (
                <span className="font-mono text-[12px] text-dim">
                  {saved.cron} · {saved.schedule.timezone}
                </span>
              )}
            </div>
            {saved && !dirty && saved.nextRuns.length > 0 && (
              <div className="text-[12px] text-muted">
                Upcoming: {saved.nextRuns.map((r) => when(r)).join(" · ")}
              </div>
            )}
          </div>
        </Panel>

        {/* latest summary */}
        <Panel
          title="Latest scan"
          subtitle={latest ? `${when(latest.finishedAt)} · ${modelName(latest.provider, providers)} · ${latest.trigger === "schedule" ? "scheduled" : "manual"}` : undefined}
        >
          {!latest ? (
            <Empty>No scans yet. Run one now or turn on the schedule.</Empty>
          ) : (
            <RunSummary run={latest} />
          )}
        </Panel>
      </div>

      {/* history */}
      <Panel title="Scan history" subtitle="Click a scan to see the findings that appeared or were resolved.">
        {runs.length === 0 ? (
          <Empty>No scans yet.</Empty>
        ) : (
          <Table
            head={[
              { label: "Started" },
              { label: "Trigger" },
              { label: "Model" },
              { label: "Status" },
              { label: "Users checked", right: true },
              { label: "Findings", right: true },
              { label: "New", right: true },
              { label: "Resolved", right: true },
              { label: "Revoke", right: true },
            ]}
          >
            {runs.map((r) => (
              <tr
                key={r.id}
                onClick={() => setOpenId(openId === r.id ? null : r.id)}
                className={`cursor-pointer border-b border-line2 hover:bg-hover ${openId === r.id ? "bg-hover" : ""}`}
              >
                <td className="px-2 py-2 text-text3">{when(r.startedAt)}</td>
                <td className="px-2 py-2 text-text3">{r.trigger === "schedule" ? "Scheduled" : "Manual"}</td>
                <td className="px-2 py-2 text-text3">
                  {modelName(r.provider, providers)}
                  {r.modelFallbacks > 0 && (
                    <span className="ml-2" title="Model calls that failed and fell back to rules">
                      <Chip tone="warn">{r.modelFallbacks} fallback</Chip>
                    </span>
                  )}
                </td>
                <td className="px-2 py-2">
                  {r.status === "running" ? (
                    <Chip>
                      running {r.progress.done}/{r.progress.total || "…"}
                    </Chip>
                  ) : r.status === "failed" ? (
                    <span title={r.error}>
                      <Chip tone="bad">failed</Chip>
                    </span>
                  ) : (
                    <span className="text-[12px] text-muted">done · {duration(r)}</span>
                  )}
                </td>
                <td className="px-2 py-2 text-right font-mono text-text3">
                  {r.usersReviewed}
                  <span className="text-dim">/{r.usersTotal}</span>
                </td>
                <td className="px-2 py-2 text-right font-mono text-text3">{r.findingsTotal}</td>
                <td className={`px-2 py-2 text-right font-mono ${r.newFindings.length ? "text-[#f58aa0]" : "text-dim"}`}>
                  {r.previousRunId ? `+${r.newFindings.length}` : "—"}
                </td>
                <td className={`px-2 py-2 text-right font-mono ${r.resolvedFindings.length ? "text-[#7fd1a8]" : "text-dim"}`}>
                  {r.previousRunId ? `−${r.resolvedFindings.length}` : "—"}
                </td>
                <td className="px-2 py-2 text-right font-mono text-text3">{r.verdicts.revoke}</td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {open && open.status !== "running" && (
        <Panel
          title={`Scan of ${when(open.startedAt)}`}
          subtitle={open.previousRunId ? "Compared with the scan before it." : "First scan, so there is nothing to compare with."}
          action={
            <button onClick={() => setOpenId(null)} className="rounded px-2 py-1 text-[12px] text-muted hover:bg-hover hover:text-ink3">
              Close
            </button>
          }
        >
          {open.status === "failed" ? (
            <ErrorBox>{open.error ?? "The scan failed."}</ErrorBox>
          ) : (
            <div className="flex flex-col gap-5">
              <RunSummary run={open} />
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <ChangeList title="New findings" rows={open.newFindings} tone="bad" empty={open.previousRunId ? "No new findings." : "—"} />
                <ChangeList title="Resolved findings" rows={open.resolvedFindings} tone="good" empty={open.previousRunId ? "Nothing resolved." : "—"} />
              </div>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

function RunSummary({ run }: { run: ScanRun }) {
  const s = run.summary;
  return (
    <div className="flex flex-col gap-4">
      {s && (
        <div>
          <div className="mb-1 font-mono text-[11px] uppercase tracking-wide text-dim">{s.engine === "llm" ? "AI summary" : "Summary"}</div>
          <p className="m-0 text-[14px] leading-snug text-ink3">{s.headline}</p>
          {s.highlights.length > 0 && (
            <ul className="m-0 mt-2 list-disc space-y-1 pl-5 text-[13px] text-text3">
              {s.highlights.map((h, i) => (
                <li key={i}>{h}</li>
              ))}
            </ul>
          )}
          {s.actions.length > 0 && (
            <>
              <div className="mt-3 text-[11px] uppercase tracking-wide text-dim">Next steps</div>
              <ul className="m-0 mt-1 list-disc space-y-1 pl-5 text-[13px] text-text3">
                {s.actions.map((h, i) => (
                  <li key={i}>{h}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
        <Mini label="Flagged users" value={run.flaggedUsers} />
        <Mini label="Findings" value={run.findingsTotal} />
        <Mini label="New" value={run.previousRunId ? run.newFindings.length : "—"} tone={run.newFindings.length ? "bad" : undefined} />
        <Mini label="Resolved" value={run.previousRunId ? run.resolvedFindings.length : "—"} tone={run.resolvedFindings.length ? "good" : undefined} />
        <Mini label="Revoke" value={run.verdicts.revoke} />
        <Mini label="Review" value={run.verdicts.review} />
      </div>
    </div>
  );
}

function Mini({ label, value, tone }: { label: string; value: number | string; tone?: "bad" | "good" }) {
  return (
    <div className="rounded border border-line bg-ink2 px-2.5 py-1.5">
      <div className="text-[11px] text-dim">{label}</div>
      <div className={`mt-0.5 font-mono text-[15px] ${tone === "bad" ? "text-[#f58aa0]" : tone === "good" ? "text-[#7fd1a8]" : "text-ink3"}`}>{value}</div>
    </div>
  );
}

function ChangeList({ title, rows, tone, empty }: { title: string; rows: FindingRef[]; tone: "bad" | "good"; empty: string }) {
  return (
    <div className="min-w-0">
      <div className={`mb-2 text-[13px] font-semibold ${tone === "bad" ? "text-[#f58aa0]" : "text-[#7fd1a8]"}`}>
        {title} <span className="font-mono text-[12px] font-normal text-dim">{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div className="text-[13px] text-muted">{empty}</div>
      ) : (
        <ul className="m-0 flex max-h-[320px] list-none flex-col gap-1.5 overflow-y-auto p-0 text-[13px]">
          {rows.map((f) => (
            <li key={f.key} className="flex flex-wrap items-center gap-2">
              <a href={userLink(f.userId)} className="text-ink3 no-underline hover:underline">
                {f.userName}
              </a>
              {f.appLabel && <span className="text-muted">{f.appLabel}</span>}
              <Chip tone={tone === "bad" ? "warn" : "plain"}>{RULE_LABEL[f.rule] ?? f.rule}</Chip>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Field({ label, children, group = false }: { label: string; children: React.ReactNode; group?: boolean }) {
  // Button groups aren't labelable; a <label> around them would click the first button.
  const Tag = group ? "div" : "label";
  return (
    <Tag className="flex flex-col gap-1.5 text-[11px] uppercase tracking-wide text-dim">
      {label}
      <span className="normal-case tracking-normal">{children}</span>
    </Tag>
  );
}

function ErrorBox({ children }: { children: React.ReactNode }) {
  return <div className="rounded border border-[#8a2f40] bg-[#8a2f40]/15 px-3 py-2 text-[13px] text-[#f58aa0]">{children}</div>;
}
