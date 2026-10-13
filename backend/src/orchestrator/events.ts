/**
 * Events emitted while a scan runs, streamed to the client over SSE to drive the
 * live progress screen. Timings are real (measured per tool/stage).
 */
export type ScanEvent =
  | {
      t: "start";
      mode: "repo" | "domain";
      target: string;
      startedAt: number;
      steps: { id: string; name: string; tools: string }[];
    }
  | { t: "tool"; id: string; status: "running"; at: number }
  | { t: "tool"; id: string; status: "done"; at: number; ms: number; hits: number }
  | { t: "tool"; id: string; status: "error"; at: number; ms: number; hits: number; message: string }
  | { t: "log"; at: number; source: string; message: string }
  | { t: "stage"; id: string; name: string; status: "running" | "done"; at: number; ms?: number; detail?: string }
  | { t: "done"; reportId: string; at: number; raw: number; findings: number }
  | { t: "error"; message: string };

export type EmitFn = (event: ScanEvent) => void;
