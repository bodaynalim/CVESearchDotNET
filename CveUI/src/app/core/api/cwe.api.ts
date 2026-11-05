import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { CweViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

@Injectable({ providedIn: 'root' })
export class CweApi {
  readonly #injector = inject(Injector);

  /** CWE numeric id, e.g. 1001 or "1001". */
  get(cweId: string | number): HttpResourceRef<CweViewModel | undefined> {
    return createResource<CweViewModel>(this.#injector, () => ({
      url: `/cwe/${encodePathSegment(cweId)}`,
    }));
  }
}
