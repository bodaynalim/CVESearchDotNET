import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { VendorsApi } from '../core/api/vendors.api';

@Component({
  imports: [RouterLink],
  template: `
    <!-- Search panel -->
    <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
      <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
        <h3 class="mb-3 text-base font-semibold">Search</h3>
        <input
          class="w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-[var(--color-brand)]/20"
          type="text"
          [value]="query()"
          (input)="onQuery($event)"
          placeholder="Filter vendors…"
        />
      </div>
    </section>

    <!-- Results panel -->
    <section class="rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
      <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
        <div class="mb-4 flex items-baseline gap-2">
          <h3 class="text-base font-semibold">Vendors</h3>
          @if (filtered(); as filtered_) {
            <span class="text-xs text-slate-500">({{ filtered_.length.toLocaleString() }} found)</span>
          }
        </div>
        @if (vendors.isLoading()) {
          <p class="py-6 text-sm text-slate-500">Loading vendors…</p>
        } @else if (vendors.error(); as _error) {
          <p class="py-6 text-sm text-red-600">Failed to load vendors.</p>
        } @else {
          <ul class="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            @for (vendor of filtered(); track vendor) {
              <li>
                <a
                  [routerLink]="['/vendors', vendor]"
                  class="text-sm font-medium text-[var(--color-brand)] hover:underline"
                >{{ vendor }}</a>
              </li>
            } @empty {
              <li class="py-6 text-sm text-slate-500">No vendors match this filter.</li>
            }
          </ul>
        }
      </div>
    </section>
  `,
})
export class VendorsPage {
  private readonly vendorsApi = inject(VendorsApi);

  protected readonly vendors = this.vendorsApi.getAllVendors();
  protected readonly query = signal('');

  protected readonly filtered = computed(() => {
    const needle = this.query().toLowerCase();
    const list = this.vendors.value() ?? [];
    return needle ? list.filter(v => v.toLowerCase().includes(needle)) : list;
  });

  protected onQuery(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
  }
}
