import { HttpResourceRef, HttpResourceRequest } from '@angular/common/http';
import { inject, Injectable, Injector } from '@angular/core';
import { VendorProductsViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

/** Param getters keep param-driven request URLs reactive (e.g. route-param inputs). */
export type ParamFn<T> = () => T;

@Injectable({ providedIn: 'root' })
export class VendorsApi {
  readonly #injector = inject(Injector);

  getAllVendors(): HttpResourceRef<string[] | undefined> {
    return createResource<string[]>(this.#injector, () => ({ url: `/vendors` }));
  }

  search(term: ParamFn<string | undefined>): HttpResourceRef<string[] | undefined> {
    return createResource<string[]>(this.#injector, () => {
      // Empty/undefined term → idle (no request); typing → server-backed prefix search.
      const value = term();
      const normalized = value?.trim();
      return normalized ? ({ url: `/vendors/search/${encodePathSegment(normalized)}` } as HttpResourceRequest) : undefined;
    });
  }

  getProducts(vendorGetter: ParamFn<string>): HttpResourceRef<VendorProductsViewModel | undefined> {
    return createResource<VendorProductsViewModel>(this.#injector, () => ({
      url: `/vendors/${encodePathSegment(vendorGetter())}`,
    }));
  }
}
