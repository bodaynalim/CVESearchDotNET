import { App } from './app';
import { bootApp } from './testing/boot-app';

describe('App shell', () => {
  it('renders the app title and links to the main sections', async () => {
    const { fixture } = await bootApp();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('CveUI');
    expect(compiled.querySelector('a[href="/"]')).toBeTruthy(); // Vulnerabilities (lookup)
    expect(compiled.querySelector('a[href="/vendors"]')).toBeTruthy(); // Vendors & Products
  });
});
