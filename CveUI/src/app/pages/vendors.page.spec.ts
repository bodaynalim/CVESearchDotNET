import { bootApp, settle } from '../testing/boot-app';

const waitReal = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe('VendorsPage (routed through the app shell)', () => {
  it('lists all vendors while browsing (no search active)', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle();
    http.expectOne('http://test-api/vendors').flush(['akamai', 'nvidia', 'tenable']);
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('akamai');
    expect(compiled.textContent).toContain('nvidia');
    expect(compiled.textContent).toContain('tenable');
  });

  it('shows a loading state before the response arrives', async () => {
    const { fixture, router, http } = await bootApp();

    // The initial-boot redirect to /vendors already fired the request.
    await router.navigate(['/vendors']);
    await settle();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Loading vendors');

    http.expectOne('http://test-api/vendors').flush([]);
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No vendors match this search');
  });

  it('debounces input and searches vendors server-side', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle();
    http.expectOne('http://test-api/vendors').flush(['micro', 'cisco']);
    await fixture.whenStable();

    // Partial input fires nothing until the debounce settles.
    const input = (fixture.nativeElement as HTMLElement).querySelector('input')!;
    input.value = 'micr';
    input.dispatchEvent(new Event('input'));
    await settle();
    expect(http.match(r => r.url.includes('/vendors/search/')).length).toBe(0);

    // Advance beyond the debounce window: exactly one server search is issued.
    await waitReal(300);
    await settle();
    http.expectOne('http://test-api/vendors/search/micr').flush(['microsoft', 'micron']);
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('microsoft');
    expect(compiled.textContent).toContain('micron');
    expect(compiled.textContent).not.toContain('cisco');
  });

  it('notes when the search result set hits the API limit', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle();
    http.expectOne('http://test-api/vendors').flush([]);
    await fixture.whenStable();

    const input = (fixture.nativeElement as HTMLElement).querySelector('input')!;
    input.value = 'a';
    input.dispatchEvent(new Event('input'));
    await waitReal(300);
    await settle();
    http.expectOne('http://test-api/vendors/search/a').flush(Array.from({ length: 1000 }, (_, i) => `v${i}`));
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Showing the first');
  });

  it('returns to the full list when the search is cleared', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle();
    http.expectOne('http://test-api/vendors').flush(['nvidia', 'tenable']);
    await fixture.whenStable();

    const input = (fixture.nativeElement as HTMLElement).querySelector('input')!;
    input.value = 'ten';
    input.dispatchEvent(new Event('input'));
    await waitReal(300);
    await settle();
    http.expectOne('http://test-api/vendors/search/ten').flush(['tenable']);
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('tenable');
    expect((fixture.nativeElement as HTMLElement).textContent).not.toContain('nvidia');

    input.value = '';
    input.dispatchEvent(new Event('input'));
    await waitReal(300);
    await settle();
    // Clearing idles the search resource — no request for the empty term.
    expect(http.match(r => r.url.includes('/vendors/search/')).length).toBe(0);
    // Browse-all mode is restored without refetching.
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('nvidia');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('tenable');
  });

  it('shows a failure state when the server search fails', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle();
    http.expectOne('http://test-api/vendors').flush([]);
    await fixture.whenStable();

    const input = (fixture.nativeElement as HTMLElement).querySelector('input')!;
    input.value = 'mic';
    input.dispatchEvent(new Event('input'));
    await waitReal(300);
    await settle();
    http.expectOne('http://test-api/vendors/search/mic').flush('boom', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Failed to load vendors');
  });

  it('shows a failure state when the vendor list errors', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigate(['/vendors']);
    await settle();
    http.expectOne('http://test-api/vendors').flush('boom', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Failed to load vendors');
  });
});
