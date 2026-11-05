# The CVE list URL is the source of truth for all list state

The merged `/cves` page serializes its full listing state as query params and binds them as component inputs: `vendor`/`product` (optional drill-down scope, absent = the global list), `q` (submitted keyword), `page`, `count`, `sort` (`published`|`modified`), `direction` (`asc`|`desc`), with `/` redirecting to `/cves` so the list is the app's default view. Refresh, back/forward, and deep links all restore state because only the URL carries it — the page holds none of it itself.

Decided over a separate `/search` page for globals (one screen, one request shape, one URL grammar to document), and over in-page state because a shareable/bookmarkable result set was a requirement for this tool.

Consequences:
- New keywords take effect only on submit (Enter/Search button), and a changed `q` resets `page` to 1; sort/size changes keep the page unless the result set no longer covers it.
- The Weaknesses page (`/cwe`) follows the same contract (`q`, `page`, `count`).
- Any new listing state must land in the URL first, with an input binding and a spec — in-page-only state is a violation of this record.
