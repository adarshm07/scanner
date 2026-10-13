import type { ScanEvent } from "../types";

/**
 * POST a scan and read the server's SSE stream, invoking onEvent for each event.
 * Uses fetch streaming (not EventSource) so the request can carry a JSON body.
 */
export async function streamScan(
  endpoint: string,
  body: unknown,
  onEvent: (e: ScanEvent) => void
): Promise<void> {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok || !res.body) {
    let message = "Scan failed";
    try {
      message = (await res.json()).error ?? message;
    } catch {
      /* non-JSON error */
    }
    throw new Error(message);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE frames are separated by a blank line.
    let idx: number;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const line = frame.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      try {
        onEvent(JSON.parse(line.slice(5).trim()) as ScanEvent);
      } catch {
        /* ignore malformed frame */
      }
    }
  }
}
