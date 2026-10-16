import { useState } from "react";
import type { FixPlan } from "../types";
import { CopyBlock } from "./CopyBlock";

/**
 * Domain reports: copy-paste config for the header, cookie and HTTPS findings, for the
 * platform the site appears to run on (preselected) and the other common ones.
 */
export function FixPanel({ plan }: { plan: FixPlan }) {
  const [active, setActive] = useState(plan.platforms[0]?.id);
  const current = plan.platforms.find((p) => p.id === active) ?? plan.platforms[0];
  if (!current) return null;

  return (
    <section aria-labelledby="fix-h" className="flex flex-col gap-4 px-6 pt-8">
      <div className="flex flex-col gap-1">
        <h2 id="fix-h" className="m-0 text-[20px] font-semibold tracking-[-0.01em]">
          Fix it
        </h2>
        <p className="m-0 text-[13px] text-muted">
          {plan.detected
            ? `Detected ${plan.platforms.find((p) => p.id === plan.detected)?.label} (${plan.detectedFrom}). Config for the other platforms is in the tabs.`
            : "Couldn't tell what serves this site; pick your server or platform."}
        </p>
      </div>

      <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[13px] text-text3">
        {plan.changes.map((c) => (
          <li key={c} className="flex gap-2">
            <span aria-hidden className="text-dim">→</span>
            <span>{c}</span>
          </li>
        ))}
      </ul>

      <div role="tablist" aria-label="Server or platform" className="inline-flex w-fit max-w-full flex-wrap gap-1 rounded border border-edge p-1">
        {plan.platforms.map((p) => (
          <button
            key={p.id}
            type="button"
            role="tab"
            aria-selected={p.id === current.id}
            onClick={() => setActive(p.id)}
            className={`cursor-pointer rounded border-0 px-3 py-1.5 text-[13px] ${
              p.id === current.id ? "bg-panel2 text-ink3" : "bg-transparent text-muted hover:text-text3"
            }`}
          >
            {p.label}
            {p.id === plan.detected && <span className="ml-1.5 text-[11px] text-dim">detected</span>}
          </button>
        ))}
      </div>

      <div role="tabpanel" className="flex max-w-[900px] flex-col gap-2">
        <CopyBlock label={current.file} text={current.snippet} />
        {current.notes.length > 0 && (
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[12.5px] text-muted">
            {current.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        )}
        <p className="m-0 text-[12.5px] text-muted">
          The Content-Security-Policy starts in report-only mode so it can't break the site: watch the browser console,
          adjust, then rename the header to Content-Security-Policy. Re-run the scan after deploying.
        </p>
      </div>
    </section>
  );
}
