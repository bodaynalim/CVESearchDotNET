import { bootApp, settle } from '../testing/boot-app';

describe('VendorProductsPage (routed through the app shell)', () => {
  it('requests the vendor by URL-encoding "/" as %2F and lists its products', async () => {
    const { fixture, http, router } = await bootApp();

    // Vendor name containing a slash, as a browser delivers a deep-linked URL:
    // %2F in the raw path decodes to "/" in the route param, and the API client
    // re-encodes it back when building the request.
    await router.navigateByUrl('/vendors/akamai%2Fzstd');
    await settle();
    http
      .expectOne('http://test-api/vendors/akamai%2Fzstd')
      .flush({ vendor: 'akamai/zstd', softwares: ['keystone', 'wss'] });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('keystone');
    expect(compiled.textContent).toContain('wss');
  });

  it('shows a vendor-not-found state on HTTP 404', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigate(['/vendors/ghost']);
    await settle();
    http.expectOne('http://test-api/vendors/ghost').flush('ghost is not found', {
      status: 404,
      statusText: 'Not Found',
    });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Vendor not found');
  });

  it('shows a generic failure state on a server error', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigate(['/vendors/nasa']);
    await settle();
    http.expectOne('http://test-api/vendors/nasa').flush('boom', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Failed to load products');
  });
});
