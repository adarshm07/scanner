/**
 * LLM provider abstraction. The pipeline only ever asks a provider to turn a
 * system+user message into text; JSON coercion is shared here.
 */

export type ProviderId = "claude" | "gemini" | "openai";

export interface LlmMessage {
  system: string;
  user: string;
  maxTokens?: number;
}

export interface LlmProvider {
  readonly id: ProviderId;
  generate(msg: LlmMessage): Promise<string>;
}

/**
 * Parse a JSON object out of an LLM response. Tolerates ```json fences and
 * surrounding prose by extracting the outermost {...} block as a fallback.
 */
export function extractJson<T>(text: string): T {
  const cleaned = text
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```\s*$/i, "")
    .trim();
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start !== -1 && end !== -1) {
      return JSON.parse(cleaned.slice(start, end + 1)) as T;
    }
    throw new Error("LLM did not return valid JSON");
  }
}
