import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { VendorProductsViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

@Injectable({ providedIn: 'root' })
export class VendorsApi {
  readonly #injector = inject(Injector);

  getAllVendors(): HttpResourceRef<string[] | undefined> {
    return createResource<string[]>(this.#injector, () => ({ url: `/vendors` }));
  }

  search(search: () => string): HttpResourceRef<string[] | undefined> {
    return createResource<string[]>(this.#injector, () => ({
      url: `/vendors/search/${encodePathSegment(search())}`,
    }));
  }

  getProducts(vendor: () => string): HttpResourceRef<VendorProductsViewModel | undefined> {
    return createResource<VendorProductsViewModel>(this.#injector, () => ({
      url: `/vendors/${encodePathSegment(vendor())}`,
    }));
  }
}
