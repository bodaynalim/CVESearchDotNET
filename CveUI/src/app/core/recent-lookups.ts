import { Injectable, signal } from '@angular/core';

const STORAGE_KEY = 'cveui.recentLookups';
const MAX_ENTRIES = 5;

/**
 * Recently looked-up CVE IDs, local-only per spec (no backend persistence).
 * Newest first, deduplicated, capped at MAX_ENTRIES.
 */
@Injectable({ providedIn: 'root' })
export class RecentLookups {
  private static readonly MAX = MAX_ENTRIES;

  readonly entries = signal<string[]>(RecentLookups.read());

  add(cveId: string): void {
    const normalized = cveId.trim().toUpperCase();
    if (!normalized) return;
    this.entries.update(current =>
      [normalized, ...current.filter(entry => entry !== normalized)].slice(0, RecentLookups.MAX),
    );
    this.persist();
  }

  clear(): void {
    this.entries.set([]);
    this.persist();
  }

  private static read(): string[] {
    try {
      const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
      const parsed: unknown = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === 'string') : [];
    } catch {
      return []; // privacy modes/disabled storage degrade to no history
    }
  }

  private persist(): void {
    try {
      globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(this.entries()));
    } catch {
      // Same degradation as read(): ignore storage failures.
    }
  }
}
