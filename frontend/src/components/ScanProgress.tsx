import { useEffect, useMemo, useRef, useState } from "react";
import type { ScanEvent } from "../types";

interface Row {
  id: string;
  name: string; // tool/source label (mono)
  check: string; // human check name
  startAt?: number;
  endAt?: number;
  status: "pending" | "running" | "done" | "error";
  detail?: string;
}

interface Derived {
  startedAt: number | null;
  target: string;
  rows: Row[];
  rawHits: number;
  logs: { at: number; source: string; message: string }[];
  lastAt: number;
  done: boolean;
}

function derive(events: ScanEvent[]): Derived {
  let startedAt: number | null = null;
  let target = "";
  const order: string[] = [];
  const rows = new Map<string, Row>();
  const logs: Derived["logs"] = [];
  let rawHits = 0;
  let lastAt = 0;
  let done = false;

  const ensure = (id: string, name: string, check: string) => {
    if (!rows.has(id)) {
      rows.set(id, { id, name, check, status: "pending" });
      order.push(id);
    }
    return rows.get(id)!;
  };

  for (const e of events) {
    if ("at" in e && typeof e.at === "number") lastAt = Math.max(lastAt, e.at);
    switch (e.t) {
      case "start":
        startedAt = e.startedAt;
        target = e.target;
        lastAt = Math.max(lastAt, e.startedAt);
        for (const s of e.steps) ensure(s.id, s.id, s.name);
        break;
      case "tool": {
        const r = ensure(e.id, e.id, e.id);
        if (e.status === "running") {
          r.status = "running";
          r.startAt = e.at;
        } else if (e.status === "error") {
          r.status = "error";
          r.endAt = e.at;
          r.detail = `not scanned: ${e.message}`;
          rawHits += e.hits;
        } else {
          r.status = "done";
          r.endAt = e.at;
          r.detail = `${e.hits} ${e.hits === 1 ? "hit" : "hits"}`;
          rawHits += e.hits;
        }
        break;
      }
      case "stage": {
        const r = ensure(e.id, e.id, e.name);
        r.name = e.id;
        r.check = e.name;
        if (e.status === "running") {
          r.status = r.status === "done" ? "done" : "running";
          r.startAt = r.startAt ?? e.at;
        } else {
          r.status = "done";
          r.endAt = e.at;
          if (e.detail) r.detail = e.detail;
        }
        break;
      }
      case "log":
        logs.push({ at: e.at, source: e.source, message: e.message });
        break;
      case "done":
        done = true;
        lastAt = Math.max(lastAt, e.at);
        break;
      case "error":
        done = true;
        break;
    }
  }

  return {
    startedAt,
    target,
    rows: order.map((id) => rows.get(id)!),
    rawHits,
    logs,
    lastAt,
    done,
  };
}

function fmt(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

/** Durations: "8.4s" under a minute, "4:07" after (one decimal stops mattering by then). */
export function fmtDuration(ms: number): string {
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const total = Math.floor(s);
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
}

/** Axis labels: whole seconds, or m:ss past a minute ("90s" reads worse than "1:30"). */
function fmtTick(sec: number): string {
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, "0")}`;
}

const TICK_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800];
/** Smallest "nice" step that keeps the axis to at most ~7 labels, however long the scan runs. */
export function tickStepFor(totalSecs: number): number {
  return TICK_STEPS.find((s) => totalSecs / s <= 7) ?? TICK_STEPS[TICK_STEPS.length - 1];
}

export function ScanProgress({ events }: { events: ScanEvent[] }) {
  const d = useMemo(() => derive(events), [events]);
  const [now, setNow] = useState(Date.now());
  const logRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (d.done) return;
    const id = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(id);
  }, [d.done]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [d.logs.length]);

  const started = d.startedAt ?? now;
  const clock = d.done ? d.lastAt : now;
  const elapsedMs = Math.max(0, clock - started);
  // Timeline window: at least 4s so bars are visible early.
  const windowMs = Math.max(4000, elapsedMs);
  const totalSecs = Math.ceil(windowMs / 1000);
  const tickStep = tickStepFor(totalSecs);
  // Only round multiples of the step: no trailing "current second" label that jumps every
  // tick and collides with its neighbour.
  const tickLabels = Array.from({ length: Math.floor(totalSecs / tickStep) + 1 }, (_, i) => i * tickStep);

  return (
    <div className="border border-line bg-ink">
      <header className="flex items-start gap-6 border-b border-line px-6 py-5">
        <div className="flex-1">
          <h1 className="m-0 text-[24px] font-semibold tracking-[-0.01em]">
            {d.done ? "Scan finished" : "Scanning…"}
          </h1>
          <p className="mt-1 max-w-[560px] text-[13.5px] leading-normal text-muted">
            Scanners run in parallel. Hits are deduplicated when the last scanner exits,
            then the model explains each one. Nothing is reported as a finding before that.
          </p>
        </div>
        <div className="flex gap-10 text-right">
          <div>
            <div className="text-[12px] text-muted">Elapsed</div>
            {/* Fixed width + tabular digits: the header doesn't shift as the number grows. */}
            <div className="min-w-[6.5ch] font-mono text-[28px] font-medium tabular-nums tracking-[-0.02em]">
              {fmtDuration(elapsedMs)}
            </div>
          </div>
          <div>
            <div className="text-[12px] text-muted">Raw hits</div>
            <div className="font-mono text-[28px] font-medium tracking-[-0.02em]">{d.rawHits}</div>
          </div>
        </div>
      </header>

      {/* timeline table */}
      <div className="px-6 pt-4">
        <div className="grid grid-cols-[24px_130px_150px_minmax(0,1fr)_200px_60px] items-center gap-4 border-b border-line pb-2 text-[12px] text-muted">
          <span />
          <span>Step</span>
          <span>Check</span>
          <span className="relative">
            {tickLabels.map((i) => {
              const pos = (i * 1000) / windowMs;
              return (
                <span
                  key={i}
                  className="absolute top-0 whitespace-nowrap font-mono text-[11px] tabular-nums"
                  // Centre each label on its tick; pin the edges so nothing overflows the column.
                  style={{
                    left: `${pos * 100}%`,
                    transform: i === 0 ? undefined : pos > 0.95 ? "translateX(-100%)" : "translateX(-50%)",
                  }}
                >
                  {fmtTick(i)}
                </span>
              );
            })}
          </span>
          <span>Progress</span>
          <span className="text-right">Time</span>
        </div>

        {d.rows.map((r) => {
          const start = r.startAt ?? started;
          const end = r.endAt ?? (r.status === "running" ? clock : start);
          const left = ((start - started) / windowMs) * 100;
          const width = Math.max(0.5, ((end - start) / windowMs) * 100);
          const ms = r.endAt && r.startAt ? r.endAt - r.startAt : r.status === "running" ? clock - start : 0;
          return (
            <div
              key={r.id}
              className="grid grid-cols-[24px_130px_150px_minmax(0,1fr)_200px_60px] items-center gap-4 border-b border-line2 py-2.5"
            >
              <span className="flex justify-center">
                {r.status === "done" ? (
                  <svg width={13} height={13} viewBox="0 0 12 12" aria-hidden="true">
                    <path d="M2.5 6.5 L5 9 L9.5 3.5" fill="none" stroke="#56B982" strokeWidth={1.8} />
                  </svg>
                ) : r.status === "error" ? (
                  <svg width={13} height={13} viewBox="0 0 12 12" aria-label="Not scanned">
                    <path d="M2 2 L10 10 M10 2 L2 10" stroke="#F0506E" strokeWidth={1.8} />
                  </svg>
                ) : r.status === "running" ? (
                  <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-sev-medium" />
                ) : (
                  <span className="h-2.5 w-2.5 rounded-full border border-edge" />
                )}
              </span>
              <span className="font-mono text-[13px]">{r.name}</span>
              <span className="text-[13px] text-text3">{r.check}</span>
              <span className="relative h-3.5">
                <span
                  className="absolute top-1/2 h-2 -translate-y-1/2 rounded-[2px]"
                  style={{
                    left: `${left}%`,
                    width: `${width}%`,
                    background: r.status === "running" ? "#4A555E" : "#5E6870",
                  }}
                />
              </span>
              <span
                className={`truncate font-mono text-[12.5px] ${r.status === "error" ? "text-sev-critical" : "text-text3"}`}
                title={r.detail}
              >
                {r.detail ?? (r.status === "running" ? "running…" : "")}
              </span>
              <span className="text-right font-mono text-[12.5px] tabular-nums text-muted">
                {ms > 0 ? fmtDuration(ms) : ""}
              </span>
            </div>
          );
        })}
      </div>

      {/* output log */}
      <div className="px-6 pb-6 pt-5">
        <div className="flex items-baseline gap-3 pb-2">
          <span className="text-[13px] font-medium">Output</span>
          <span className="text-[12px] text-muted">interleaved, newest last</span>
        </div>
        <pre
          ref={logRef}
          className="m-0 max-h-[180px] overflow-auto border border-line bg-ink2 p-3.5 font-mono text-[12px] leading-[1.7] text-text3"
        >
          {d.logs.length === 0
            ? "  waiting for scanners…"
            : d.logs
                .map((l) => `${fmt(l.at)}   ${l.source.padEnd(12)}${l.message}`)
                .join("\n")}
        </pre>
      </div>
    </div>
  );
}
