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

  searchByProduct(params: CveSearchParams): HttpResourceRef<CveViewModel[] | undefined> {
    const { vendor, product, count, page, descending, byPublished } = params;
    // The backend validates count/page range (>= 1) and answers 400 on
    // invalid values, which pages surface via error().
    return createResource<CveViewModel[]>(this.#injector, () => ({
      url: `/cve/search/${encodePathSegment(vendor)}/${encodePathSegment(product)}/${count}/${page}/${descending}/${byPublished}`,
    }));
  }

  searchCount(vendor: string, product: string): HttpResourceRef<CveSearchCount | undefined> {
    return createResource<CveSearchCount>(this.#injector, () => ({
      url: `/cve/search/${encodePathSegment(vendor)}/${encodePathSegment(product)}/count`,
    }));
  }

  get(cveId: string): HttpResourceRef<CveViewModel | undefined> {
    return createResource<CveViewModel>(this.#injector, () => ({
      url: `/cve/${encodePathSegment(cveId)}`,
    }));
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
