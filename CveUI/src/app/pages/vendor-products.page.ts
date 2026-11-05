import { Component, computed, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { isApiNotFound } from '../core/api/api.http';
import { VendorsApi } from '../core/api/vendors.api';

@Component({
  imports: [RouterLink],
  template: `
    <a routerLink="/vendors" class="mb-4 inline-block text-sm text-slate-400 hover:text-sky-300">← All vendors</a>
    @if (products.isLoading()) {
      <p class="text-slate-400">Loading products…</p>
    } @else if (notFound()) {
      <p class="text-red-400">Vendor not found.</p>
    } @else if (products.error(); as _error) {
      <p class="text-red-400">Failed to load products.</p>
    } @else if (products.value(); as data) {
      <h2 class="mb-4 text-xl font-semibold text-slate-100">{{ data.Vendor }}</h2>
      <ul class="grid grid-cols-1 gap-1 sm:grid-cols-2 lg:grid-cols-3">
        @for (product of data.Softwares; track product) {
          <li class="rounded bg-slate-800 px-2 py-1 font-mono text-sm">{{ product }}</li>
        } @empty {
          <li class="text-slate-400">No products known for this vendor.</li>
        }
      </ul>
    }
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
}
