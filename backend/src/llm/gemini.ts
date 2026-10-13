import { LlmMessage, LlmProvider } from "./provider";
import { runCommand } from "../tools/util";

/**
 * Gemini (Google Generative AI) provider.
 */
export class GeminiProvider implements LlmProvider {
  readonly id = "gemini" as const;

  constructor(private apiKey: string, private model: string) {
  }

  async generate(msg: LlmMessage): Promise<string> {
    const payload = JSON.stringify({
      systemInstruction: { parts: [{ text: msg.system }] },
      contents: [{ parts: [{ text: msg.user }] }],
      generationConfig: { maxOutputTokens: msg.maxTokens ?? 2048 },
    });
    const response = await runCommand(
      "curl",
      [
        "-sS",
        "--fail-with-body",
        "-H",
        "Content-Type: application/json",
        "-H",
        `x-goog-api-key: ${this.apiKey}`,
        "-d",
        payload,
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
          this.model
        )}:generateContent`,
      ],
      { timeoutMs: 60000 }
    );
    let data: {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
      error?: { message?: string };
    };
    try {
      data = JSON.parse(response.stdout) as typeof data;
    } catch {
      throw new Error(response.stderr || "Gemini returned invalid JSON");
    }
    if (response.code !== 0) {
      throw new Error(
        `Gemini API: ${data.error?.message ?? (response.stderr || "request failed")}`
      );
    }
    const text = data.candidates?.[0]?.content?.parts
      ?.map((part) => part.text ?? "")
      .join("");
    if (!text) {
      throw new Error("Gemini API returned no text content");
    }
    return text;
  }
}
