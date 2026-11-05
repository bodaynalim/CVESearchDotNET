import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { App } from '../app';
import { appConfig } from '../app.config';
import { API_BASE_URL } from '../core/api/api.http';

/**
 * Boots the full app shell (shell routing + HTTP stack already live inside
 * appConfig.providers) with a testing HTTP backend at the API boundary.
 * Behavior is driven through real routing and rendering — never by touching
 * component internals.
 */
/**
 * Yields one macrotask so scheduler effects (change detection, httpResource
 * request creation for newly activated routes) run before assertions.
 * NOTE: `fixture.whenStable()` must only be awaited AFTER pending API
 * requests have been flushed — it hangs while a request is in flight.
 */
export function settle(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 0));
}

export async function bootApp(): Promise<{
  fixture: ReturnType<typeof TestBed.createComponent<App>>;
  router: Router;
  http: HttpTestingController;
}> {
  await TestBed.configureTestingModule({
    imports: [App],
    providers: [
      ...appConfig.providers,
      { provide: API_BASE_URL, useValue: 'http://test-api' },
      provideHttpClientTesting(),
    ],
  }).compileComponents();

  const fixture = TestBed.createComponent(App);
  fixture.autoDetectChanges();
  return {
    fixture,
    router: TestBed.inject(Router),
    http: TestBed.inject(HttpTestingController),
  };
}
