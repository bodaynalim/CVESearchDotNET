import { Injector } from '@angular/core';
import { RecentLookups } from './recent-lookups';

/**
 * Each test builds a fresh root-less injector per service instance, because
 * RecentLookups reads localStorage at construction time (a shared
 * providedIn-root instance would freeze the first read for the whole suite).
 */
function createService(): RecentLookups {
  const injector = Injector.create({ providers: [RecentLookups] });
  return injector.get(RecentLookups);
}

describe('RecentLookups', () => {
  beforeEach(() => {
    localStorage.removeItem('cveui.recentLookups');
  });

  it('starts with history from localStorage', () => {
    localStorage.setItem('cveui.recentLookups', JSON.stringify(['CVE-2024-0002', 'CVE-2024-0001']));
    expect(createService().entries()).toEqual(['CVE-2024-0002', 'CVE-2024-0001']);
  });

  it('adds newest-first, deduplicated, uppercase', () => {
    const service = createService();
    service.add('CVE-2024-0001');
    service.add('CVE-2024-0002');
    service.add('cve-2024-0001'); // duplicate, re-promoted to newest
    expect(service.entries()).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
    expect(localStorage.getItem('cveui.recentLookups')).toEqual(
      JSON.stringify(['CVE-2024-0001', 'CVE-2024-0002']),
    );
  });

  it('caps the history at five entries', () => {
    const service = createService();
    for (let i = 1; i <= 7; i++) {
      service.add(`CVE-2024-000${i}`);
    }
    expect(service.entries()).toEqual([
      'CVE-2024-0007',
      'CVE-2024-0006',
      'CVE-2024-0005',
      'CVE-2024-0004',
      'CVE-2024-0003',
    ]);
  });

  it('clears history and persists the empty list', () => {
    const service = createService();
    service.add('CVE-2024-0001');
    service.clear();
    expect(service.entries()).toEqual([]);
    expect(localStorage.getItem('cveui.recentLookups')).toBe('[]');
  });
});
