import { Component, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { isApiNotFound } from '../core/api/api.http';
import { VendorsApi } from '../core/api/vendors.api';

@Component({
  imports: [RouterLink],
  template: `
    <section class="rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
      <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
        <a routerLink="/vendors" class="inline-block text-sm text-[var(--color-brand)] hover:underline">← All vendors</a>

        @if (products.isLoading()) {
          <p class="py-6 text-sm text-slate-500">Loading products…</p>
        } @else if (notFound()) {
          <p class="py-6 text-sm text-red-600">Vendor not found.</p>
        } @else if (products.error(); as _error) {
          <p class="py-6 text-sm text-red-600">Failed to load products.</p>
        } @else if (products.value(); as data) {
          <div class="mt-3 mb-4 flex items-baseline gap-2">
            <h3 class="text-base font-semibold">{{ data.Vendor }}</h3>
            <span class="text-xs text-slate-500">({{ data.Softwares.length.toLocaleString() }} products)</span>
          </div>

          <p class="mb-3 text-xs font-semibold tracking-wide text-slate-500 uppercase">Filter products</p>
          <input
            class="mb-4 w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-[var(--color-brand)]/20"
            type="text"
            [value]="query()"
            (input)="onQuery($event)"
            placeholder="Filter products…"
          />

          <ul class="flex flex-wrap gap-2">
            @for (product of filtered(); track product) {
              <li>
                <span class="rounded-full bg-[var(--color-brand)]/10 px-3 py-1 font-mono text-xs text-[var(--color-brand)]">
                  {{ product }}
                </span>
              </li>
            } @empty {
              <li class="py-4 text-sm text-slate-500">No products match this filter.</li>
            }
          </ul>
        }
      </div>
    </section>
  `,
})
export class VendorProductsPage {
  // Bound from the route param (`withComponentInputBinding`); the resource url
  // re-evaluates whenever the route param changes because it reads the input
  // signal inside the reactive url factory.
  readonly vendor = input.required<string>();

  private readonly vendorsApi = inject(VendorsApi);

  protected readonly products = this.vendorsApi.getProducts(() => this.vendor());

  protected readonly notFound = computed(() => isApiNotFound(this.products.error()));

  protected readonly query = signal('');

  protected readonly filtered = computed(() => {
    const needle = this.query().toLowerCase();
    const softwares = this.products.value()?.Softwares ?? [];
    return needle ? softwares.filter(v => v.toLowerCase().includes(needle)) : softwares;
  });

  protected onQuery(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
  }
}
