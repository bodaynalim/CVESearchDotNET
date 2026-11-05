import { Component, inject, signal } from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { filter, map, startWith } from 'rxjs';

@Component({
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  private readonly router = inject(Router);

  // Header reflects the active section; route data is not wired up yet.
  protected readonly sectionTitle = toSignal(
    this.router.events.pipe(
      filter((event): event is NavigationEnd => event instanceof NavigationEnd),
      map(event => (event.url.startsWith('/vendors') ? 'Vendors & Products' : 'Vulnerabilities')),
      startWith('Vulnerabilities'),
    ),
    { initialValue: 'Vulnerabilities' },
  );
}
