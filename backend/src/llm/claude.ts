import Anthropic from "@anthropic-ai/sdk";
import { GuardrailBlockedError, LlmMessage, LlmProvider } from "./provider";

/**
 * Claude (Anthropic) provider.
 */
export class ClaudeProvider implements LlmProvider {
  readonly id = "claude" as const;
  private client: Anthropic;

  constructor(apiKey: string, private model: string) {
    this.client = new Anthropic({ apiKey });
  }

  async generate(msg: LlmMessage): Promise<string> {
    const res = await this.client.messages.create({
      model: this.model,
      max_tokens: msg.maxTokens ?? 2048,
      system: msg.system,
      messages: [{ role: "user", content: msg.user }],
    });
    if ((res.stop_reason as string) === "refusal") {
      throw new GuardrailBlockedError("response blocked (refusal)");
    }
    return res.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");
  }
}
