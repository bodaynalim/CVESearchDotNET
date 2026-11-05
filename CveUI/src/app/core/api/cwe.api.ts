import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { CweViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

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
}
