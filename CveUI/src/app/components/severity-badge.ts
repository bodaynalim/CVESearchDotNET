import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { resolveCvssSeverity } from '../core/severity';

/** Color-coded CVSS severity badge, e.g. [9.8 Critical], with the vector on hover. */
@Component({
  selector: 'cveui-severity-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span
      class="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold text-white"
      [class]="badgeClass()"
      [title]="vector()"
    >
      @if (displayScore(); as score) {
        <span class="font-mono font-bold">{{ score }}</span>
      }
      {{ label() }}
    </span>
  `,
})
export class SeverityBadge {
  /** Severity string straight from the API ("HIGH"/"Medium"/"CRITICAL"/…); null acceptable. */
  readonly severityRaw = input<string | undefined | null>();
  /** Base score as fallback for the label and formatting. */
  readonly baseScore = input<number | undefined>();
  /** Which CVSS generation this badge represents (pure-function fallback). */
  readonly version = input.required<'v2' | 'v3'>();
  readonly vector = input<string | undefined>();

  protected readonly resolved = computed(() =>
    resolveCvssSeverity(this.severityRaw(), this.baseScore(), this.version()),
  );

  protected readonly label = computed(() => this.resolved().severity ?? 'N/A');

  protected readonly displayScore = computed(() => {
    const score = this.baseScore();
    return score === undefined || score === null ? null : score.toFixed(1);
  });

  protected readonly badgeClass = computed(() =>
    'cveui-severity ' + this.resolved().badgeClass,
  );
}
