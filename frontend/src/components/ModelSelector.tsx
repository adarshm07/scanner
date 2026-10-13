import type { ProviderDescriptor, ProviderId } from "../types";

interface ModelSelectorProps {
  providers: ProviderDescriptor[];
  value: ProviderId | null;
  onChange: (id: ProviderId) => void;
}

function statusLabel(p: ProviderDescriptor): string {
  if (p.available) return "";
  if (!p.enabled) return " — disabled";
  return " — no API key";
}

export function ModelSelector({ providers, value, onChange }: ModelSelectorProps) {
  const noneAvailable = providers.length > 0 && providers.every((p) => !p.available);
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-[13px] font-medium text-muted">Triage model</label>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value as ProviderId)}
        className="h-10 w-full rounded border border-edge bg-ink2 px-3 text-[13.5px] text-ink3 outline-none focus:border-muted"
      >
        {providers.length === 0 && <option value="">Deterministic only</option>}
        {providers.map((p) => (
          <option key={p.id} value={p.id} disabled={!p.available}>
            {p.label} ({p.model}){statusLabel(p)}
          </option>
        ))}
      </select>
      {noneAvailable && (
        <p className="text-[12px] text-dim">
          No model available — scans run in deterministic-only mode.
        </p>
      )}
    </div>
  );
}
