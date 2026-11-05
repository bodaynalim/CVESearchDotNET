import { HttpResourceRef, HttpResourceRequest, httpResource } from '@angular/common/http';
import { Injector, runInInjectionContext } from '@angular/core';

/**
 * Creates an httpResource inside the caller's injector context, since
 * `httpResource()` itself must execute in an injection context (NG0203)
 * even when invoked from a plain service method. The spec factory may
 * return `undefined`, which puts the resource in idle state (no request).
 */
export function createResource<T>(
  injector: Injector,
  spec: () => HttpResourceRequest | undefined,
): HttpResourceRef<T | undefined> {
  return runInInjectionContext(injector, () => httpResource<T>(spec));
}
