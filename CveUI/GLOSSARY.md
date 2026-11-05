# CveUI

The Angular SPA (the "UI project") that browses the CVE Search API. It is read-only, holds no server-side state, and treats URLs as the browsable source of truth for list state.

## Language

### Navigation

**Vulnerabilities page**:
The app's default view (the CVE list): paginated CVE results, optionally scoped by vendor/product, optionally filtered by a Keyword.
_Avoid_: home, search page

**CVE lookup**:
Opening a single CVE by exact ID from the entry field on the Vulnerabilities page; recordings of recent successful lookups live only in the browser.
_Avoid_: quick search, detail search

**Global CVE search**:
Browsing all CVEs with no vendor/product scope; the same list page, just unscoped.
_Avoid_: all-CVEs view

**Weaknesses page**:
The CWE list entry of the main navigation: paginated CWE entries in ascending numeric-ID order with a Keyword filter on ID or name.
_Avoid_: cwe list, weaknesses search

**Vendors & Products**:
The drill-down navigation section: search vendors, then pick a product to reach a scoped Vulnerabilities page.

### Listing mechanics

**Keyword**:
A single submitted search phrase (Enter or Search button) carried in the URL; case-insensitive substring matching is defined API-side.
_Avoid_: live search, filter (reserved for vendor/product scoping)

**Result set**:
The full match behind a listing — one count request serves all the pagination page turns for the same Result set.

**Severity badge**:
The color-classified CVSS chip on rows and detail pages; entries without CVSS data display "Not scored" instead.

### Browser-local data

**Recent lookups**:
The last five successfully opened CVE IDs, kept only in the browser's localStorage; failed lookups must never pollute them.

**Recent lookup chip**:
A one-click deep link rendered from Recent lookups on the Vulnerabilities page.
