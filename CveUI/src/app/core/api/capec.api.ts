import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { CapecViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

@Injectable({ providedIn: 'root' })
export class CapecApi {
  readonly #injector = inject(Injector);

  /**
   * CAPEC numeric id, e.g. 92 or "92". A getter returning undefined idles
   * the resource (no request).
   */
  get(idGetter: () => string | number | undefined): HttpResourceRef<CapecViewModel | undefined> {
    return createResource<CapecViewModel>(this.#injector, () => {
      const capecId = idGetter();
      return capecId === undefined ? undefined : { url: `/capec/${encodePathSegment(capecId)}` };
    });
  }
}
