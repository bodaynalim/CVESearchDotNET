import { bootApp, settle } from '../testing/boot-app';

describe('CapecDetailPage (routed through the app shell)', () => {
  it('renders the attack pattern with severity, prerequisites and solutions', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/capec/92');
    await settle();
    http.expectOne('http://test-api/capec/92').flush({
      name: 'Forced Integer Overflow',
      capecId: '92',
      summary: 'This attack forces an integer variable to go out of range.',
      prerequisites: ['Attacker can manipulate the variable'],
      solutions: ['Use a language or compiler that performs automatic bounds checking.'],
      relatedCapecs: [],
      relatedCwes: ['CWE-190'],
      severity: 'High',
      likelyhoodAttack: 'Low',
      taxonomy: [],
      executionFlowTypeAttacks: [],
    });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('CAPEC-92');
    expect(compiled.textContent).toContain('Forced Integer Overflow');
    expect(compiled.textContent).toContain('Severity:');
    expect(compiled.textContent).toContain('Attacker can manipulate the variable');
    expect(compiled.textContent).toContain('Use a language or compiler');
  });

  it('links related CWEs to their pages and shows not-found on unknown ids', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/capec/999');
    await settle();
    http.expectOne('http://test-api/capec/999').flush('not found', {
      status: 404,
      statusText: 'Not Found',
    });
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('CAPEC not found');
  });

  it('renders related weaknesses as links, degrading non-linkable markers to text', async () => {
    const { fixture, http, router } = await bootApp();

    await router.navigateByUrl('/capec/92');
    await settle();
    http.expectOne('http://test-api/capec/92').flush({
      name: 'Forced Integer Overflow',
      capecId: '92',
      summary: 'This attack forces an integer variable to go out of range.',
      prerequisites: [],
      solutions: [],
      relatedCwes: ['190', 'NVD-CWE-noinfo'],
      relatedCapecs: ['128'],
      severity: 'High',
      likelyhoodAttack: 'Low',
      taxonomy: [],
      executionFlowTypeAttacks: [],
    });
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('a[href="/cwe/190"]')?.textContent).toContain('190');
    expect(compiled.textContent).toContain('NVD-CWE-noinfo'); // degraded, not dropped
    expect(compiled.querySelector('a[href="/capec/128"]')?.textContent).toContain('128');
  });
});
