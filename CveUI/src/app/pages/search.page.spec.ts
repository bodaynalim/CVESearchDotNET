import { bootApp, settle } from '../testing/boot-app';

describe('SearchPage (routed through the app shell)', () => {
  it('navigates to the CVE detail page for a valid CVE ID', async () => {
    const { fixture, router, http, } = await bootApp();

    await router.navigateByUrl('/');
    await settle();

    const page = (fixture.nativeElement as HTMLElement).querySelector('form')!;
    const input = page.querySelector('input')!;
    input.value = 'cve-2018-0001';
    input.dispatchEvent(new Event('input'));

    page.dispatchEvent(new Event('submit'));
    await settle();

    http.expectOne('http://test-api/cve/CVE-2018-0001').flush(sampleCve());
    await fixture.whenStable();

    expect(router.url).toBe('/cves/CVE-2018-0001');
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('cve-2018-0001'.toUpperCase());
  });

  it('rejects invalid IDs with a hint instead of navigating', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigateByUrl('/');
    await settle();

    const page = (fixture.nativeElement as HTMLElement).querySelector('form')!;
    const input = page.querySelector('input')!;
    input.value = 'not-a-cve';
    input.dispatchEvent(new Event('input'));
    page.dispatchEvent(new Event('submit'));
    await settle();

    expect(router.url).toBe('/');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('is not a valid CVE ID');
    expect(http.match(() => true).length).toBe(0);
  });
});

function sampleCve() {
  return {
    cveId: 'CVE-2018-0001',
    assigner: 'certcc',
    published: '2018-01-12T00:00:00Z',
    modified: '2018-01-12T00:00:00Z',
    cwes: ['CWE-20'],
    summary: 'An issue was discovered in Product X.',
    Cvss2: null,
    Cvss3: { BaseScore: 5.3, VectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    referencesUrls: ['https://example.com/advisory'],
    vulnerableConfigurations: ['cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*'],
  };
}
