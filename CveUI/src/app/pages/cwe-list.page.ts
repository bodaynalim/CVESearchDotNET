import { Component, computed, effect, inject, input, untracked } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { CweApi, CweListRequest } from '../core/api/cwe.api';

const PAGE_SIZES = [10, 25, 50, 100] as const;
const DEFAULT_PAGE_SIZE = 25;

export function parsePage(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : 1;
}

export function parsePageSize(value: string | undefined): number {
  const parsed = PAGE_SIZES.find(size => String(size) === value);
  return parsed ?? DEFAULT_PAGE_SIZE;
}

export function parseKeyword(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

@Component({
  imports: [DecimalPipe, RouterLink],
  template: `
    <form (submit)="submitSearch(searchBox.value)" class="mb-4 flex items-center gap-2" role="search">
      <input
        #searchBox
        name="q"
        type="search"
        placeholder="Keyword in CWE ID or name"
        [value]="keyword() ?? ''"
        class="w-64 max-w-full rounded border border-slate-300 bg-white px-3 py-1.5 text-sm"
        aria-label="Search weaknesses by keyword (CWE ID or name)"
      />
      <button
        type="submit"
        class="rounded bg-[var(--color-brand)] px-4 py-1.5 text-sm font-semibold text-white hover:opacity-90"
      >Search</button>
      <label class="ml-auto text-xs text-slate-500">
        Per page
        <select
          #countSelect
          (change)="setPageSize(countSelect.value)"
          class="mx-1 rounded border border-slate-300 bg-white px-2 py-1"
        >
          @for (size of pageSizes; track size) {
            <option [value]="size" [selected]="pageSize() === size">{{ size }}</option>
          }
        </select>
      </label>
    </form>

    @if (results.isLoading()) {
      <p class="py-6 text-sm text-slate-500">Loading weaknesses...</p>
    } @else if (results.error()) {
      <p class="py-6 text-sm text-red-600">Failed to load weaknesses.</p>
    } @else if (results.value(); as list) {
      <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
        <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
          <div class="mb-4 flex items-baseline gap-2">
            <h3 class="text-base font-semibold">Weaknesses</h3>
            @if (total(); as totalCount) {
              <span class="text-xs text-slate-500">({{ totalCount | number: '1.0-0' : 'en-US' }} found)</span>
            }
          </div>

          @if (list.length === 0) {
            <p class="py-6 text-sm text-slate-500">No weaknesses found.</p>
          } @else {
            <ul class="divide-y divide-slate-200">
              @for (cwe of list; track cwe.cweId) {
                <li class="py-3 first:pt-0 last:pb-0">
                  <div class="flex items-baseline justify-between gap-4">
                    <a
                      [routerLink]="['/cwe', cwe.cweId]"
                      class="font-mono text-sm font-medium text-[var(--color-brand)] hover:underline"
                    >CWE-{{ cwe.cweId }}</a>
                  </div>
                  <p class="text-sm font-medium text-slate-800">{{ cwe.name }}</p>
                  <p class="mt-1 line-clamp-2 text-sm text-slate-700" [title]="cwe.description">{{ cwe.description }}</p>
                </li>
              }
            </ul>
          }
        </div>
      </section>

      @if (totalPages() > 1 && list.length > 0) {
        <div class="flex items-center justify-between rounded-md border border-[var(--color-card-border)] bg-white px-5 py-3 shadow-sm">
          <button
            type="button"
            (click)="goToPage(pageNumber() - 1)"
            [disabled]="pageNumber() <= 1"
            class="rounded border border-slate-300 px-3 py-1 text-sm text-slate-700 hover:border-[var(--color-brand)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            &lt; Previous
          </button>
          <span class="text-sm text-slate-600">Page {{ pageNumber() }} of {{ totalPages() }}</span>
          <button
            type="button"
            (click)="goToPage(pageNumber() + 1)"
            [disabled]="pageNumber() >= totalPages()"
            class="rounded border border-slate-300 px-3 py-1 text-sm text-slate-700 hover:border-[var(--color-brand)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next &gt;
          </button>
        </div>
      }
    }
  `,
})
export class CweListPage {
  // URL-as-source-of-truth, as on the CVE list page.
  readonly q = input<string>();
  readonly page = input<string>();
  readonly count = input<string>();

  protected readonly pageSizes = PAGE_SIZES;
  protected readonly pageSize = computed(() => parsePageSize(this.count()));
  protected readonly pageNumber = computed(() => parsePage(this.page()));
  protected readonly keyword = computed(() => parseKeyword(this.q()));

  private readonly cweApi = inject(CweApi);
  private readonly router = inject(Router);

  private readonly listRequest = computed<CweListRequest>(() => {
    const keyword = this.keyword();
    return keyword ? { kind: 'keyword', keyword } : { kind: 'all' };
  });

  protected readonly results = this.cweApi.list(() => ({
    ...this.listRequest(),
    count: this.pageSize(),
    page: this.pageNumber(),
  }));

  // Count refetches only when the result set changes - never on page turns.
  private readonly totalCount = this.cweApi.listCount(this.listRequest);

  protected readonly total = computed(() => {
    if (this.totalCount.error()) return undefined;
    return this.totalCount.value()?.total;
  });

  protected readonly totalPages = computed(() => {
    const total = this.total();
    return total === undefined ? 1 : Math.max(1, Math.ceil(total / this.pageSize()));
  });

  // A page-size drop can shrink the match set below the current page: clamp
  // back into range instead of rendering an empty page.
  constructor() {
    effect(() => {
      const total = this.total();
      if (total === undefined) return;
      const count = untracked(this.pageSize);
      const page = untracked(this.pageNumber);
      const last = Math.max(1, Math.ceil(total / count));
      if (page > last) {
        this.patchQueryParams({ page: last });
      }
    });
  }

  protected goToPage(target: number): void {
    const clamped = Math.min(Math.max(1, target), this.totalPages());
    if (clamped === this.pageNumber()) return;
    this.patchQueryParams({ page: clamped });
  }

  protected setPageSize(value: string): void {
    if (Number.parseInt(value, 10) === this.pageSize()) return;
    this.patchQueryParams({ count: value });
  }

  /** Submits the keyword box: new phrase lands in the URL and resets to page 1. */
  protected submitSearch(term: string): void {
    const q = parseKeyword(term) ?? null; // null removes the query param
    const queryParams: Record<string, string | number | null> = { q };
    if ((this.keyword() ?? null) !== q) {
      queryParams['page'] = null;
    }
    void this.router.navigate([], { queryParams, queryParamsHandling: 'merge' });
  }

  private patchQueryParams(queryParams: Record<string, string | number | null>): void {
    void this.router.navigate([], { queryParams, queryParamsHandling: 'merge' });
  }
}
