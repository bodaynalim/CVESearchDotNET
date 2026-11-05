import { Injectable, signal } from '@angular/core';
import { normalizeCveId } from './cve-id';

export const RECENT_LOOKUPS_STORAGE_KEY = 'cveui.recentLookups';
const MAX_ENTRIES = 5;

/**
 * Recently looked-up CVE IDs, local-only per spec (no backend persistence).
 * Newest first, deduplicated (normalized), capped at MAX_ENTRIES.
 */
@Injectable({ providedIn: 'root' })
export class RecentLookups {
  readonly entries = signal<string[]>(RecentLookups.read());

  add(cveId: string): void {
    const normalized = normalizeCveId(cveId);
    if (!normalized) return;
    this.entries.update(current =>
      [normalized, ...current.filter(entry => entry !== normalized)].slice(0, MAX_ENTRIES),
    );
    this.persist();
  }

  clear(): void {
    this.entries.set([]);
    this.persist();
  }

  private static read(): string[] {
    try {
      const raw = globalThis.localStorage?.getItem(RECENT_LOOKUPS_STORAGE_KEY);
      const parsed: unknown = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed)
        ? parsed
            .filter((entry): entry is string => typeof entry === 'string' && entry.trim() !== '')
            .map(normalizeCveId)
            .reduce<string[]>((unique, entry) => (unique.includes(entry) ? unique : [...unique, entry]), [])
            .slice(0, MAX_ENTRIES)
        : [];
    } catch {
      return []; // privacy modes/disabled storage degrade to no history
    }
  }

  private persist(): void {
    try {
      globalThis.localStorage?.setItem(RECENT_LOOKUPS_STORAGE_KEY, JSON.stringify(this.entries()));
    } catch {
      // Same degradation as read(): ignore storage failures.
    }
  }
}
