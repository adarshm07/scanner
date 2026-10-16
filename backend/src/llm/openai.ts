import OpenAI from "openai";
import { LlmMessage, LlmProvider } from "./provider";

/**
 * OpenAI-compatible provider: an AI gateway (e.g. TrueFoundry, when OPENAI_BASE_URL is set)
 * or the OpenAI API directly (when it isn't). Non-streaming.
 *
 * Requests are bounded: a hung gateway fails after OPENAI_TIMEOUT_MS (default 60s, one
 * retry) and triage falls back for that batch, instead of stalling the scan for the SDK's
 * default 10 minutes x 3 attempts.
 */
const TIMEOUT_MS = Number(process.env.OPENAI_TIMEOUT_MS) || 60_000;
export class OpenAiProvider implements LlmProvider {
  readonly id = "openai" as const;
  private client: OpenAI;

  constructor(apiKey: string, baseURL: string, private model: string) {
    const gateway = baseURL.trim();
    this.client = new OpenAI({
      apiKey,
      timeout: TIMEOUT_MS,
      maxRetries: 1,
      ...(gateway
        ? {
            baseURL: gateway,
            // Gateway request logging stays on: usage is tracked per key. Secrets are masked
            // before triage (see tools/secrets.ts), so logged prompts never contain them.
            defaultHeaders: {
              "X-TFY-METADATA": "{}",
              "X-TFY-LOGGING-CONFIG": '{"enabled": true}',
            },
          }
        : {}),
    });
  }

  async generate(msg: LlmMessage): Promise<string> {
    const res = await this.client.chat.completions.create({
      model: this.model,
      max_tokens: msg.maxTokens ?? 2048,
      messages: [
        { role: "system", content: msg.system },
        { role: "user", content: msg.user },
      ],
      stream: false,
    });
    return res.choices[0]?.message?.content ?? "";
  }
}
