import { useEffect, useState } from "react";

/**
 * Small localStorage layer. The backend stays the source of truth; the browser keeps a copy
 * of what it last saw (and the viewer's UI choices) so pages render instantly and survive a
 * refresh or a backend restart. Storage can be missing or throw (private windows, blocked
 * site data, quota), so every call is wrapped and failures fall back to "nothing saved".
 *
 * Bump VERSION when a stored shape changes; older entries are then ignored and cleared.
 */
const VERSION = 1;
const PREFIX = "scannerx:";
const key = (name: string) => `${PREFIX}v${VERSION}:${name}`;

interface Envelope<T> {
  savedAt: string;
  value: T;
}

function store(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/** Value and the time it was saved, or null. */
export function load<T>(name: string): Envelope<T> | null {
  try {
    const raw = store()?.getItem(key(name));
    return raw ? (JSON.parse(raw) as Envelope<T>) : null;
  } catch {
    return null;
  }
}

export function save<T>(name: string, value: T): void {
  const s = store();
  if (!s) return;
  const raw = JSON.stringify({ savedAt: new Date().toISOString(), value } satisfies Envelope<T>);
  try {
    s.setItem(key(name), raw);
  } catch {
    // Quota: drop our other cached data (not UI preferences) and try once more.
    try {
      clearCache();
      s.setItem(key(name), raw);
    } catch {
      /* give up; the app works without the cache */
    }
  }
}

export function remove(name: string): void {
  try {
    store()?.removeItem(key(name));
  } catch {
    /* ignore */
  }
}

/** Removes cached server data (keys under "cache/"), keeping UI preferences. */
export function clearCache(): void {
  const s = store();
  if (!s) return;
  try {
    for (const k of Object.keys(s)) if (k.startsWith(`${key("cache/")}`)) s.removeItem(k);
  } catch {
    /* ignore */
  }
}

/** Removes entries written by an older VERSION. */
function sweepOldVersions() {
  const s = store();
  if (!s) return;
  try {
    for (const k of Object.keys(s)) if (k.startsWith(PREFIX) && !k.startsWith(`${PREFIX}v${VERSION}:`)) s.removeItem(k);
  } catch {
    /* ignore */
  }
}
sweepOldVersions();

/** useState that is remembered across reloads. */
export function usePersistentState<T>(name: string, initial: T): [T, (v: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    const saved = load<T>(name);
    // Merge objects so new fields added later get their defaults.
    if (saved && typeof initial === "object" && initial !== null && !Array.isArray(initial)) {
      return { ...initial, ...(saved.value as object) } as T;
    }
    return saved ? saved.value : initial;
  });
  useEffect(() => save(name, value), [name, value]);
  return [value, setValue];
}

/** "just now", "5 min ago", "3 h ago", or a date. */
export function savedAgo(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}
