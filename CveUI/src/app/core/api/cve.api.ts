import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { CveSearchCount, CveViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

export interface CveSearchParams {
  vendor: string;
  product: string;
  count: number;
  page: number;
  descending: boolean;
  byPublished: boolean;
}

@Injectable({ providedIn: 'root' })
export class CveApi {
  readonly #injector = inject(Injector);

  /**
   * Paginated vendor+product CVE search. The params getter may return
   * undefined to idle the resource (e.g. until a vendor/product is known).
   * The backend validates count/page range (>= 1) with a 400; the page layer
   * is responsible for sending well-formed values.
   */
  searchByProduct(
    paramsGetter: () => CveSearchParams | undefined,
  ): HttpResourceRef<CveViewModel[] | undefined> {
    return createResource<CveViewModel[]>(this.#injector, () => {
      const { vendor, product, count, page, descending, byPublished } = paramsGetter() ?? {};
      if (vendor === undefined || product === undefined) return undefined;
      return {
        url: `/cve/search/${encodePathSegment(vendor)}/${encodePathSegment(product)}/${count}/${page}/${descending}/${byPublished}`,
      };
    });
  }

  /** Total matched CVEs for a vendor+product pair; refetches when either changes. */
  searchCount(
    vendorGetter: () => string | undefined,
    productGetter: () => string | undefined,
  ): HttpResourceRef<CveSearchCount | undefined> {
    return createResource<CveSearchCount>(this.#injector, () => {
      const vendor = vendorGetter();
      const product = productGetter();
      if (vendor === undefined || product === undefined) return undefined;
      return {
        url: `/cve/search/${encodePathSegment(vendor)}/${encodePathSegment(product)}/count`,
      };
    });
  }

  get(cveIdGetter: () => string | undefined): HttpResourceRef<CveViewModel | undefined> {
    return createResource<CveViewModel>(this.#injector, () => {
      const cveId = cveIdGetter();
      return cveId === undefined ? undefined : { url: `/cve/${encodePathSegment(cveId)}` };
    });
  }

  lastPublished(vendor: string, product: string): HttpResourceRef<CveViewModel | undefined> {
    return createResource<CveViewModel>(this.#injector, () => ({
      url: `/cve/last/published/${encodePathSegment(vendor)}/${encodePathSegment(product)}`,
    }));
  }

  lastModified(vendor: string, product: string): HttpResourceRef<CveViewModel | undefined> {
    return createResource<CveViewModel>(this.#injector, () => ({
      url: `/cve/last/modified/${encodePathSegment(vendor)}/${encodePathSegment(product)}`,
    }));
  }
}
