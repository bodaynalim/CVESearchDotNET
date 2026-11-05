import { bootApp, settle } from '../testing/boot-app';

describe('VendorsPage (routed through the app shell)', () => {
  it('lists all vendors from the API', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle(); // let the activated route's resource fire its request
    http.expectOne('http://test-api/vendors').flush(['akamai', 'nvidia', 'tenable']);
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('akamai');
    expect(compiled.textContent).toContain('nvidia');
    expect(compiled.textContent).toContain('tenable');
  });

  it('shows a loading state before the response arrives', async () => {
    const { fixture, router, http } = await bootApp();

    // The redirect to /vendors already fired the request.
    await router.navigate(['/vendors']);
    await settle();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Loading vendors');

    http.expectOne('http://test-api/vendors').flush([]);
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No vendors available');
  });
});
