import OpenAI from "openai";
import { LlmMessage, LlmProvider } from "./provider";

/**
 * OpenAI-compatible provider (TrueFoundry gateway). Streams the response and
 * concatenates the deltas.
 */
export class OpenAiProvider implements LlmProvider {
  readonly id = "openai" as const;
  private client: OpenAI;

  constructor(apiKey: string, baseURL: string, private model: string) {
    this.client = new OpenAI({
      apiKey,
      baseURL,
      defaultHeaders: {
        "X-TFY-METADATA": "{}",
        "X-TFY-LOGGING-CONFIG": '{"enabled": true}',
      },
    });
  }

  async generate(msg: LlmMessage): Promise<string> {
    const stream = await this.client.chat.completions.create({
      model: this.model,
      max_tokens: msg.maxTokens ?? 2048,
      messages: [
        { role: "system", content: msg.system },
        { role: "user", content: msg.user },
      ],
      stream: true,
    });
    let out = "";
    for await (const chunk of stream) {
      out += chunk.choices[0]?.delta?.content ?? "";
    }
    return out;
  }
}
