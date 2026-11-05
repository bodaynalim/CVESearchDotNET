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

/** Global (or keyword) list request — vendor/product filtering is done with searchByProduct instead. */
export type CveListQuery =
  | { kind: 'all'; count: number; page: number; descending: boolean; byPublished: boolean }
  | { kind: 'keyword'; keyword: string; count: number; page: number; descending: boolean; byPublished: boolean };

export type CveListCountQuery = { kind: 'all' } | { kind: 'keyword'; keyword: string };

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

  /**
   * Global CVE list: request getter returns undefined to idle, 'all' for the
   * whole database, or 'keyword' for the submitted search phrase.
   */
  list(requestGetter: () => CveListQuery | undefined): HttpResourceRef<CveViewModel[] | undefined> {
    return createResource<CveViewModel[]>(this.#injector, () => {
      const request = requestGetter();
      if (request === undefined) return undefined;
      const { count, page, descending, byPublished } = request;
      const prefix =
        request.kind === 'all'
          ? '/cve/all'
          : `/cve/search/${encodePathSegment(request.keyword)}`;
      return { url: `${prefix}/${count}/${page}/${descending}/${byPublished}` };
    });
  }

  /** Total matched CVEs for the current list request (all or keyword). */
  listCount(requestGetter: () => CveListCountQuery | undefined): HttpResourceRef<CveSearchCount | undefined> {
    return createResource<CveSearchCount>(this.#injector, () => {
      const request = requestGetter();
      if (request === undefined) return undefined;
      return {
        url: request.kind === 'all' ? '/cve/all/count' : `/cve/search-count/${encodePathSegment(request.keyword)}`,
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
