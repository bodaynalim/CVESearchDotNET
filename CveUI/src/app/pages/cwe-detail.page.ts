import { DatePipe } from '@angular/common';
import { Component, computed, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { isApiNotFound } from '../core/api/api.http';
import { CweApi } from '../core/api/cwe.api';
import { normalizeCveId } from '../core/cve-id';

export function parseCweNumericId(value: string): number | null {
  const match = /^(\d+)$/.exec(value);
  return match ? Number.parseInt(match[1], 10) : null;
}

export function cweRouteParam(cweEntry: string): string | null {
  // CVEs reference weaknesses as "CWE-<n>" (or occasionally non-numeric
  // markers like "NVD-CWE-noinfo", which have no detail page).
  const match = /^CWE-(\d+)$/i.exec(cweEntry.trim());
  return match ? match[1] : null;
}

@Component({
  imports: [RouterLink],
  template: `
    @if (invalidId()) {
      <p class="py-6 text-sm text-red-600">Not a valid CWE ID.</p>
    } @else if (cwe.isLoading()) {
      <p class="py-6 text-sm text-slate-500">Loading weakness…</p>
    } @else if (notFound()) {
      <p class="py-6 text-sm text-red-600">CWE not found.</p>
    } @else if (cwe.error()) {
      <p class="py-6 text-sm text-red-600">Failed to load CWE.</p>
    } @else if (cwe.value(); as data) {
      <section class="rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
        <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
          <a routerLink="/" class="mb-4 inline-block text-sm text-[var(--color-brand)] hover:underline">← Home</a>
          <div class="mt-3 mb-1 flex flex-wrap items-baseline gap-x-3">
            <h3 class="font-mono text-lg font-semibold">CWE-{{ data.cweId }}</h3>
          </div>
          <p class="mb-4 text-base font-semibold text-slate-800">{{ data.name }}</p>
          <p class="text-sm leading-relaxed whitespace-pre-line">{{ data.description }}</p>
        </div>
      </section>
    }
  `,
})
export class CweDetailPage {
  // Bound from the route param (`withComponentInputBinding`), numeric CWE id.
  readonly id = input.required<string>();

  private readonly cweApi = inject(CweApi);

  protected readonly parsedId = computed(() => parseCweNumericId(normalizeCveId(this.id())));

  protected readonly invalidId = computed(() => this.parsedId() === null);

  protected readonly cwe = this.cweApi.get(() => {
    const parsed = this.parsedId();
    return parsed === null ? undefined : parsed;
  });

  protected readonly notFound = computed(() => isApiNotFound(this.cwe.error()));
}
