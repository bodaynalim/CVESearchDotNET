import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { VendorsApi } from '../core/api/vendors.api';

@Component({
  imports: [RouterLink],
  template: `
    <h2 class="mb-4 text-xl font-semibold text-slate-100">Vendors</h2>
    @if (vendors.isLoading()) {
      <p class="text-slate-400">Loading vendors…</p>
    } @else if (vendors.error(); as error) {
      <p class="text-red-400">Failed to load vendors.</p>
    } @else {
      <ul class="grid grid-cols-1 gap-1 sm:grid-cols-2 lg:grid-cols-3">
        @for (vendor of vendors.value(); track vendor) {
          <li>
            <a
              [routerLink]="['/vendors', vendor]"
              class="block rounded px-2 py-1 font-mono text-sm text-sky-300 hover:bg-slate-800 hover:text-sky-200"
            >{{ vendor }}</a>
          </li>
        } @empty {
          <li class="text-slate-400">No vendors available.</li>
        }
      </ul>
    }
  `,
})
export class VendorsPage {
  protected readonly vendors = inject(VendorsApi).getAllVendors();
}
