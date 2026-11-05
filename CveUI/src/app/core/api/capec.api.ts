import { inject, Injectable, Injector } from '@angular/core';
import { HttpResourceRef } from '@angular/common/http';
import { CapecViewModel } from '../models';
import { encodePathSegment } from './encode-path';
import { createResource } from './http-resource';

@Injectable({ providedIn: 'root' })
export class CapecApi {
  readonly #injector = inject(Injector);

  get(capecId: string | number): HttpResourceRef<CapecViewModel | undefined> {
    return createResource<CapecViewModel>(this.#injector, () => ({
      url: `/capec/${encodePathSegment(capecId)}`,
    }));
  }
}
