import type { Severity } from "../types";

/**
 * Severity visual language from the Scanner-X visual identity: each severity has
 * both a color AND a distinct shape (diamond / triangle / filled dot / hollow
 * dot), so severity reads without relying on color alone.
 */
export const SEVERITY_META: Record<
  Severity,
  { label: Severity; color: string; fill: string; d: string; rank: number }
> = {
  critical: { label: "critical", color: "#F0506E", fill: "#F0506E", d: "M6 0.8 L11.2 6 L6 11.2 L0.8 6 Z", rank: 0 },
  high: { label: "high", color: "#F28C38", fill: "#F28C38", d: "M6 1.2 L11.2 10.6 L0.8 10.6 Z", rank: 1 },
  medium: { label: "medium", color: "#D9B53C", fill: "#D9B53C", d: "M1.4 6 A4.6 4.6 0 1 0 10.6 6 A4.6 4.6 0 1 0 1.4 6 Z", rank: 2 },
  low: { label: "low", color: "#6AA5E0", fill: "none", d: "M1.9 6 A4.1 4.1 0 1 0 10.1 6 A4.1 4.1 0 1 0 1.9 6 Z", rank: 3 },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function SeverityGlyph({
  severity,
  size = 12,
  strokeColor,
}: {
  severity: Severity;
  size?: number;
  strokeColor?: string;
}) {
  const m = SEVERITY_META[severity];
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" aria-hidden="true">
      <path
        d={m.d}
        fill={m.fill}
        stroke={strokeColor ?? m.color}
        strokeWidth={1.6}
        strokeLinejoin="round"
      />
    </svg>
  );
}
