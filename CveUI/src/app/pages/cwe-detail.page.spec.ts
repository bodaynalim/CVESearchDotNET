import { bootApp, settle } from '../testing/boot-app';

describe('CweDetailPage (routed through the app shell)', () => {
  it('renders the weakness name and description', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/cwe/79');
    await settle();
    http.expectOne('http://test-api/cwe/79').flush({
      cweId: '79',
      name: 'Improper Neutralization of Input',
      description: 'The product does not neutralize input.',
    });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('CWE-79');
    expect(compiled.textContent).toContain('Improper Neutralization of Input');
    expect(compiled.textContent).toContain('The product does not neutralize input.');
  });

  it('shows not-found on a missing numeric id', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/cwe/999999');
    await settle();
    http.expectOne('http://test-api/cwe/999999').flush('not found', {
      status: 404,
      statusText: 'Not Found',
    });
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('CWE not found');
  });

  it('rejects non-numeric ids without requesting', async () => {
    const { fixture, router, http } = await bootApp();

    await router.navigateByUrl('/cwe/noinfo');
    await settle();
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Not a valid CWE ID');
    expect(http.match(() => true).length).toBe(0);
  });
});
