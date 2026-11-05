import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { CweSearchCount, CweViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

/** Global CWE list request: 'all' or a submitted keyword, plus paging. */
export type CweListRequest = { kind: 'all' } | { kind: 'keyword'; keyword: string };
export type CweListQuery = CweListRequest & { count: number; page: number };

@Injectable({ providedIn: 'root' })
export class CweApi {
  readonly #injector = inject(Injector);

  /**
   * CWE numeric id, e.g. 1001 or "79". A getter returning undefined idles
   * the resource (no request).
   */
  get(idGetter: () => string | number | undefined): HttpResourceRef<CweViewModel | undefined> {
    return createResource<CweViewModel>(this.#injector, () => {
      const cweId = idGetter();
      return cweId === undefined ? undefined : { url: `/cwe/${encodePathSegment(cweId)}` };
    });
  }

  /** Paged CWE list in ascending numeric-ID order; keyword empties to 'all'. */
  list(requestGetter: () => CweListQuery | undefined): HttpResourceRef<CweViewModel[] | undefined> {
    return createResource<CweViewModel[]>(this.#injector, () => {
      const request = requestGetter();
      if (request === undefined) return undefined;
      const prefix = request.kind === 'all' ? '/cwe/all' : `/cwe/search/${encodePathSegment(request.keyword)}`;
      return { url: `${prefix}/${request.count}/${request.page}` };
    });
  }

  /** Total matched CWE entries for the current list request. */
  listCount(requestGetter: () => CweListRequest | undefined): HttpResourceRef<CweSearchCount | undefined> {
    return createResource<CweSearchCount>(this.#injector, () => {
      const request = requestGetter();
      if (request === undefined) return undefined;
      return {
        url: request.kind === 'all' ? '/cwe/all/count' : `/cwe/search-count/${encodePathSegment(request.keyword)}`,
      };
    });
  }
}
