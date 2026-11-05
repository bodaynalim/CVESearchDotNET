import { Component, computed, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { isApiNotFound } from '../core/api/api.http';
import { CapecApi } from '../core/api/capec.api';
import { normalizeCveId } from '../core/cve-id';

export function parseCapecNumericId(value: string): number | null {
  const match = /^(\d+)$/.exec(value);
  return match ? Number.parseInt(match[1], 10) : null;
}

/** "CWE-79" → "79"; other markers (e.g. "NVD-CWE-noinfo") have no page → null. */
export function cweRouteParam(cweEntry: string): string | null {
  const match = /^CWE-(\d+)$/i.exec(cweEntry.trim());
  return match ? match[1] : null;
}

@Component({
  imports: [RouterLink],
  template: `
    @if (invalidId()) {
      <p class="py-6 text-sm text-red-600">Not a valid CAPEC ID.</p>
    } @else if (capec.isLoading()) {
      <p class="py-6 text-sm text-slate-500">Loading attack pattern…</p>
    } @else if (notFound()) {
      <p class="py-6 text-sm text-red-600">CAPEC not found.</p>
    } @else if (capec.error()) {
      <p class="py-6 text-sm text-red-600">Failed to load CAPEC.</p>
    } @else if (capec.value(); as data) {
      <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
        <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
          <div class="mb-3 flex flex-wrap items-baseline gap-x-3">
            <h3 class="font-mono text-lg font-semibold">CAPEC-{{ data.capecId }}</h3>
            <span class="text-sm font-semibold text-slate-800">{{ data.name }}</span>
          </div>

          <dl class="mb-4 grid grid-cols-1 gap-1 text-sm sm:grid-cols-2">
            @if (data.severity) {
              <div><dt class="inline font-semibold">Severity:</dt> <dd class="inline text-slate-600">{{ data.severity }}</dd></div>
            }
            @if (data.likelyhoodAttack) {
              <div><dt class="inline font-semibold">Attack likelihood:</dt> <dd class="inline text-slate-600">{{ data.likelyhoodAttack }}</dd></div>
            }
          </dl>

          <p class="text-sm leading-relaxed whitespace-pre-line">{{ data.summary }}</p>
        </div>
      </section>

      @if (data.prerequisites?.length) {
        <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
          <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
            <h4 class="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">Prerequisites</h4>
            <ul class="list-disc space-y-1 pl-5 text-sm">
              @for (item of data.prerequisites; track $index) {
                <li>{{ item }}</li>
              }
            </ul>
          </div>
        </section>
      }

      @if (data.solutions?.length) {
        <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
          <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
            <h4 class="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">Solutions / mitigations</h4>
            <ul class="list-disc space-y-1 pl-5 text-sm">
              @for (item of data.solutions; track $index) {
                <li>{{ item }}</li>
              }
            </ul>
          </div>
        </section>
      }

      <section class="rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
        <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
          <h4 class="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">Related</h4>
          @if (data.relatedCwes?.length) {
            <div class="mb-2 flex flex-wrap items-center gap-2">
              <span class="text-xs text-slate-500">Weaknesses:</span>
              @for (cweEntry of data.relatedCwes; track cweEntry) {
                @if (cweRouteParam(cweEntry); as numericId) {
                  <a
                    [routerLink]="['/cwe', numericId]"
                    class="font-mono text-xs font-medium text-[var(--color-brand)] hover:underline"
                  >{{ cweEntry }}</a>
                }
              }
            </div>
          }
          @if (data.relatedCapecs?.length) {
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-xs text-slate-500">Attack patterns:</span>
              @for (relatedCapec of data.relatedCapecs; track relatedCapec) {
                @if (parseCapecId(relatedCapec); as numericId) {
                  <a
                    [routerLink]="['/capec', numericId]"
                    class="font-mono text-xs font-medium text-[var(--color-brand)] hover:underline"
                  >{{ relatedCapec }}</a>
                } @else {
                  <span class="font-mono text-xs text-slate-600">{{ relatedCapec }}</span>
                }
              }
            </div>
          }
          @if (!data.relatedCwes?.length && !data.relatedCapecs?.length) {
            <p class="py-2 text-sm text-slate-500">No related entries listed.</p>
          }
        </div>
      </section>
    }
  `,
})
export class CapecDetailPage {
  // Bound from the route param (`withComponentInputBinding`), numeric CAPEC id.
  readonly id = input.required<string>();

  private readonly capecApi = inject(CapecApi);

  protected readonly parsedId = computed(() => parseCapecNumericId(normalizeCveId(this.id())));

  protected readonly invalidId = computed(() => this.parsedId() === null);

  protected readonly capec = this.capecApi.get(() => {
    const parsed = this.parsedId();
    return parsed === null ? undefined : parsed;
  });

  protected readonly notFound = computed(() => isApiNotFound(this.capec.error()));

  // Exposed for the template's related-entry linking.
  protected readonly cweRouteParam = cweRouteParam;
  protected readonly parseCapecId = (value: string): number | null => parseCapecNumericId(value);
}
