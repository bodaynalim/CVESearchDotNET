import { bootApp, settle } from '../testing/boot-app';

function cwe(id: string, name: string) {
  return {
    cweId: id,
    name,
    description: `Description for ${name}.`,
    status: 'Stable',
    abstraction: 'Class',
    relatedCwes: [],
  };
}

describe('CweListPage (routed through the app shell)', () => {
  it('lists all CWE entries with the total, paginated by URL', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigateByUrl('/cwe');
    await settle();

    http.expectOne('http://test-api/cwe/all/25/1').flush([cwe('79', 'Cross-site Scripting'), cwe('1000', 'Research Concepts')]);
    http.expectOne('http://test-api/cwe/all/count').flush({ total: 958 });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('958 found');
    expect(compiled.textContent).toContain('CWE-79');
    expect(compiled.textContent).toContain('Cross-site Scripting');
    expect(compiled.textContent).toContain('Page 1 of 39');

    // Rows link to the existing detail pages.
    const link = compiled.querySelector<HTMLAnchorElement>('a[href="/cwe/79"]')!;
    expect(link).toBeTruthy();
  });

  it('paginates by URL without refetching the count', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/cwe');
    await settle();
    http.expectOne('http://test-api/cwe/all/25/1').flush([cwe('79', 'Cross-site Scripting')]);
    http.expectOne('http://test-api/cwe/all/count').flush({ total: 958 });
    await fixture.whenStable();

    const next = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button')).find(
      b => b.textContent!.includes('Next'),
    )!;
    next.click();
    await settle();
    expect(router.url).toContain('page=2');
    http.expectOne('http://test-api/cwe/all/25/2').flush([cwe('1001', 'Category')]);
    await fixture.whenStable();

    // The page turn must not queue another count request.
    http.expectNone(r => r.url.endsWith('/count'));
  });

  it('deep-links a keyword to the keyword endpoints and resets pagination on a fresh search', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/cwe?page=3');
    await settle();
    http.expectOne('http://test-api/cwe/all/25/3').flush([]);
    http.expectOne('http://test-api/cwe/all/count').flush({ total: 958 });
    await fixture.whenStable();

    const searchBox = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('input[name="q"]')!;
    searchBox.value = 'CWE-79';
    searchBox.form!.dispatchEvent(new Event('submit'));
    await settle();

    // A fresh keyword resets the page; the CWE- prefix is the backend's
    // business but the URL keeps what the user submitted.
    expect(router.url).toContain('q=CWE-79');
    expect(router.url).not.toContain('page=3');
    await settle();
    http.expectOne('http://test-api/cwe/search/CWE-79/25/1').flush([cwe('79', 'Cross-site Scripting')]);
    http.expectOne('http://test-api/cwe/search-count/CWE-79').flush({ total: 19 });
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('19 found');
    // The new result set issued exactly one count request of its own.
    http.expectNone(r => r.url.endsWith('/count') && r.url.includes('/cwe/all'));
  });

  it('clearing the search returns to the full list', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/cwe?q=script');
    await settle();
    http.expectOne('http://test-api/cwe/search/script/25/1').flush([]);
    http.expectOne('http://test-api/cwe/search-count/script').flush({ total: 0 });
    await fixture.whenStable();

    const searchBox = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('input[name="q"]')!;
    searchBox.value = '';
    searchBox.form!.dispatchEvent(new Event('submit'));
    await settle();

    expect(router.url).toBe('/cwe');
    await settle();
    http.expectOne('http://test-api/cwe/all/25/1').flush([cwe('79', 'Cross-site Scripting')]);
    http.expectOne('http://test-api/cwe/all/count').flush({ total: 958 });
    await fixture.whenStable();
  });

  it('shows an empty state for zero keyword matches', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/cwe?q=zzz');
    await settle();
    http.expectOne('http://test-api/cwe/search/zzz/25/1').flush([]);
    http.expectOne('http://test-api/cwe/search-count/zzz').flush({ total: 0 });
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No weaknesses found');
  });
});
