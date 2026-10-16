import type { Check } from "../types";

interface ScopeSelectorProps {
  checks: Check[];
  selected: Set<string>;
  onToggle: (id: string) => void;
}

export function ScopeSelector({ checks, selected, onToggle }: ScopeSelectorProps) {
  if (checks.length === 0) {
    return <p className="text-[13px] text-dim">Loading checks…</p>;
  }
  return (
    <div className="flex flex-col gap-2">
      <p className="text-[13px] font-medium text-muted">Checks</p>
      <div className="flex flex-col divide-y divide-line2 border border-line">
        {checks.map((check) => {
          const on = selected.has(check.id);
          return (
            <button
              key={check.id}
              type="button"
              role="switch"
              aria-checked={on}
              onClick={() => onToggle(check.id)}
              className={`flex items-start gap-3 px-3.5 py-3 text-left transition-colors hover:bg-hover ${
                on ? "bg-panel2" : "bg-transparent"
              }`}
            >
              <span
                className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-[3px] border ${
                  on ? "border-ink3 bg-ink3" : "border-edge bg-transparent"
                }`}
              >
                {on && (
                  <svg width={10} height={10} viewBox="0 0 12 12" aria-hidden="true">
                    <path d="M2.5 6.5 L5 9 L9.5 3.5" fill="none" stroke="#0F1215" strokeWidth={1.8} />
                  </svg>
                )}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-baseline gap-2">
                  <span className="text-[14px] font-medium">{check.name}</span>
                  <span className="truncate font-mono text-[11.5px] text-dim">{check.tools}</span>
                  <span className="grow" />
                  <span className="font-mono text-[11.5px] text-dim">{check.est}</span>
                </span>
                <span className="mt-0.5 block text-[12.5px] leading-snug text-muted">
                  {check.desc}
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
