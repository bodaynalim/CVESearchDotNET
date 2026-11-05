import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { Subject } from 'rxjs';
import { debounceTime } from 'rxjs/operators';
import { VendorsApi } from '../core/api/vendors.api';

const SEARCH_DEBOUNCE_MS = 250;
const MAX_SEARCH_RESULTS = 1000; // keep in sync with the API's result limit

@Component({
  imports: [RouterLink],
  template: `
    <!-- Search panel (server-backed search/autocomplete) -->
    <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
      <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
        <h3 class="mb-3 text-base font-semibold">Search</h3>
        <input
          #input
          class="w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-[var(--color-brand)]/20"
          type="text"
          role="searchbox"
          [value]="query()"
          (input)="onQuery(input.value)"
          placeholder="Search vendors…"
        />
        <p class="mt-2 text-xs text-slate-400">
          Search all matching vendors, or leave empty to browse the full list.
        </p>
      </div>
    </section>

    <!-- Results panel -->
    <section class="rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
      <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
        <div class="mb-4 flex items-baseline gap-2">
          <h3 class="text-base font-semibold">Vendors</h3>
          @if (displayed(); as list) {
            <span class="text-xs text-slate-500">({{ list.length.toLocaleString() }} found)</span>
          }
        </div>
        @if (displayedError(); as _error) {
          <p class="py-6 text-sm text-red-600">
            Failed to load vendors — the API may be unavailable. Try again shortly.
          </p>
        } @else if (displayed(); as list) {
          @if (debouncedTerm() && list.length >= MAX_SEARCH_RESULTS) {
            <p class="mb-3 text-xs text-slate-500">Showing the first {{ list.length.toLocaleString() }} matches — narrow the term to refine.</p>
          }
          <ul class="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            @for (vendor of list; track vendor) {
              <li>
                <a
                  [routerLink]="['/vendors', vendor]"
                  class="text-sm font-medium text-[var(--color-brand)] hover:underline"
                >{{ vendor }}</a>
              </li>
            } @empty {
              <li class="py-6 text-sm text-slate-500">No vendors match this search.</li>
            }
          </ul>
        } @else {
          <p class="py-6 text-sm text-slate-500">Loading vendors…</p>
        }
      </div>
    </section>
  `,
})
export class VendorsPage {
  private readonly vendorsApi = inject(VendorsApi);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly MAX_SEARCH_RESULTS = MAX_SEARCH_RESULTS;

  protected readonly allVendors = this.vendorsApi.getAllVendors();

  protected readonly query = signal('');

  readonly #queryInput = new Subject<string>();
  /** Term accepted as a search request after debouncing; empty string = idle/browse-all. */
  protected readonly debouncedTerm = signal('');

  protected readonly searchResults = this.vendorsApi.search(
    () => (this.debouncedTerm() === '' ? undefined : this.debouncedTerm()),
  );

  constructor() {
    this.#queryInput
      .pipe(debounceTime(SEARCH_DEBOUNCE_MS), takeUntilDestroyed(this.destroyRef))
      .subscribe(term => this.debouncedTerm.set(term.trim()));
  }

  protected readonly displayedError = computed(() =>
    this.debouncedTerm() === '' ? this.allVendors.error() : this.searchResults.error(),
  );

  /** While browsing (no search active) show the full list, else the search results. */
  protected readonly displayed = computed(() => {
    // Reading `.value()` on an errored resource throws; guard first.
    if (this.displayedError()) return undefined;
    return this.debouncedTerm() === '' ? this.allVendors.value() : this.searchResults.value();
  });

  protected onQuery(value: string): void {
    this.query.set(value);
    this.#queryInput.next(value);
  }
}
