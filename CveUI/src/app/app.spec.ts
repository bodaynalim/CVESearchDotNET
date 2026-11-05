import { App } from './app';
import { bootApp } from './testing/boot-app';

describe('App shell', () => {
  it('renders the app title and a link to the vendor list', async () => {
    const { fixture } = await bootApp();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('CveUI');
    expect(compiled.querySelector('a')?.getAttribute('href')).toContain('/vendors');
  });
});
