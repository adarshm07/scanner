import { config } from "../tools/util";
import {
  LlmMessage,
  LlmProvider,
  ProviderId,
  extractJson,
} from "./provider";
import { ClaudeProvider } from "./claude";
import { GeminiProvider } from "./gemini";

export type { LlmMessage, LlmProvider, ProviderId } from "./provider";

/**
 * Public description of a provider for the model selector UI.
 */
export interface ProviderDescriptor {
  id: ProviderId;
  label: string;
  model: string;
  enabled: boolean; // operator toggle
  available: boolean; // enabled AND key present -> actually usable
  isDefault: boolean;
}

interface ProviderEntry {
  descriptor: Omit<ProviderDescriptor, "isDefault">;
  create: () => LlmProvider;
}

function entries(): ProviderEntry[] {
  return [
    {
      descriptor: {
        id: "gemini",
        label: "Gemini",
        model: config.gemini.model,
        enabled: config.gemini.enabled,
        available:
          config.gemini.enabled && config.gemini.apiKey.trim().length > 0,
      },
      create: () => new GeminiProvider(config.gemini.apiKey, config.gemini.model),
    },
    {
      descriptor: {
        id: "claude",
        label: "Claude",
        model: config.claude.model,
        enabled: config.claude.enabled,
        available:
          config.claude.enabled && config.claude.apiKey.trim().length > 0,
      },
      create: () => new ClaudeProvider(config.claude.apiKey, config.claude.model),
    },
  ];
}

/** First available provider is the UI default (Gemini precedes Claude). */
function defaultId(): ProviderId | null {
  return entries().find((e) => e.descriptor.available)?.descriptor.id ?? null;
}

export function listProviders(): ProviderDescriptor[] {
  const def = defaultId();
  return entries().map((e) => ({
    ...e.descriptor,
    isDefault: e.descriptor.id === def,
  }));
}

/**
 * Resolve a usable provider for a scan. Honors the requested id when it is
 * available, otherwise falls back to the default available provider. Returns
 * null when no provider is usable (deterministic-only mode).
 */
export function resolveProvider(requestedId?: string): LlmProvider | null {
  const all = entries();
  if (requestedId) {
    const match = all.find(
      (e) => e.descriptor.id === requestedId && e.descriptor.available
    );
    if (match) return match.create();
  }
  const fallback = all.find((e) => e.descriptor.available);
  return fallback ? fallback.create() : null;
}

export function hasUsableProvider(): boolean {
  return defaultId() !== null;
}

export async function callLlm(
  provider: LlmProvider,
  msg: LlmMessage
): Promise<string> {
  return provider.generate(msg);
}

export async function callLlmJson<T>(
  provider: LlmProvider,
  msg: LlmMessage
): Promise<T> {
  return extractJson<T>(await provider.generate(msg));
}
