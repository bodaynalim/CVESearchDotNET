import { Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { CVE_ID_PATTERN, normalizeCveId } from '../core/cve-id';

@Component({
  imports: [],
  template: `
    <section class="mb-6 rounded-md border border-[var(--color-card-border)] bg-white shadow-sm">
      <div class="border-t-2 border-[var(--color-panel-accent)] px-5 py-4">
        <h3 class="mb-3 text-base font-semibold">Look up a CVE</h3>
        <form class="flex gap-3" (submit)="lookup($event, input.value)">
          <input
            #input
            class="min-w-0 flex-1 rounded border border-slate-300 bg-white px-3 py-2 font-mono text-sm outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-[var(--color-brand)]/20"
            type="text"
            placeholder="CVE-2018-0001"
            autocomplete="off"
            spellcheck="false"
          />
          <button
            type="submit"
            class="rounded bg-[var(--color-brand)] px-5 py-2 text-sm font-semibold text-white hover:bg-[var(--color-brand-hover)]"
          >
            Open
          </button>
        </form>
        @if (error(); as message) {
          <p class="mt-2 text-xs text-red-600">{{ message }}</p>
        } @else {
          <p class="mt-2 text-xs text-slate-500">Format: CVE-&lt;year&gt;-&lt;number&gt; — e.g. CVE-2018-0001</p>
        }
      </div>
    </section>
  `,
})
export class SearchPage {
  private readonly router = inject(Router);

  protected readonly error = signal<string | null>(null);

  protected lookup(event: Event, rawValue: string): void {
    event.preventDefault();
    const cveId = normalizeCveId(rawValue);

    if (!CVE_ID_PATTERN.test(cveId)) {
      this.error.set(`"${rawValue}" is not a valid CVE ID (expected format: CVE-2018-0001).`);
      return;
    }

    this.error.set(null);
    void this.router.navigate(['/cves', cveId]);
  }
}
