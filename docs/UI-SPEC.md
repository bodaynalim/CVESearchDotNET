# CVE Search UI — Specification

Status: **Draft — pending review**
Date: 2026-11-05

## 1. Goal

A standalone Angular SPA ("CveUI") that provides a searchable, browsable interface over the
existing CVE Search REST API (`Cve.Net.Search.Web`). Read-only; the API has no
mutation endpoints.

## 2. Decisions (confirmed with requester)

| Decision            | Choice                                                                 |
|---------------------|------------------------------------------------------------------------|
| Tech stack          | Angular (standalone components) + TypeScript + Tailwind CSS            |
| Project location    | New sibling folder `CveUI/` at repo root, own `package.json`           |
| Scope               | CVE search + CVE detail + vendors/products + CWE + CAPEC               |
| Hosting             | Separate origin (Angular dev server, port 4200) talking to API via CORS |
| CORS                | API's `Cors:Origins` config updated to include `http://localhost:4200`   |
| API base URL        | Angular `environment` files (dev vs prod)                              |
| Search UX           | Vendor → product drill-down **plus** direct CVE-ID lookup               |
| Look & feel         | OpenCVE-style (reference screenshot in `docs/`): dark indigo sidebar, light content area, white card panels with a top accent border, indigo link buttons, product chips, colored CVSS severity badges. |

## 3. API Contract (what the UI consumes)

Base: `https://localhost:<api-port>` (config in `CveUI/src/environments/`).

### CVEs
| Endpoint | Params | Returns |
|---|---|---|
| `GET /cve/search/{vendor}/{product}/{count}/{page}/{descending}/{byPublished}` | vendor, product (URL-encode `/` as `%2F`); count ≥ 1; page ≥ 1; descending: bool; byPublished: bool | `CveViewModel[]` |
| `GET /cve/search/{vendor}/{product}/count` | vendor, product | `{ total: long }` |
| `GET /cve/{cveId}` | e.g. `CVE-2018-0001` | `CveViewModel` (404 if unknown) |
| `GET /cve/last/published/{vendor}/{product}` | vendor, product | `CveViewModel` |
| `GET /cve/last/modified/{vendor}/{product}` | vendor, product | `CveViewModel` |

### Vendors
| Endpoint | Returns |
|---|---|
| `GET /vendors` | all vendors |
| `GET /vendors/search/{search}` | `string[]` (max 1000, prefix/name match) |
| `GET /vendors/{vendor}` | `VendorProductsViewModel` (products of vendor) |

### CWE / CAPEC
| Endpoint | Returns |
|---|---|
| `GET /cwe/{cweId}` (numeric, e.g. `1001`) | `CweViewModel` |
| `GET /capec/{capecId}` | `CapecViewModel` |

### `CveViewModel` fields the UI renders
`cveId`, `assigner`, `published`, `modified`, `cwes[]`, `summary`,
`cvss2` / `cvss3` (each has `baseScore` + vector), `referencesUrls[]`
(Url, Name, Refsource), `vulnerableConfigurations[]` (CPE 2.3 URI strings).
All JSON property names are **camelCase**: the API runs Newtonsoft JSON
(`AddNewtonsoftJson()`), whose default camelCase contract resolver wins over
the System.Text.Json options registered alongside it (verified against live
endpoints on 2026-11-05).

## 4. Screens & Routes

| Route | Screen | Notes |
|---|---|---|
| `/` | Home / Search | Global search bar with CVE-ID lookup: `CVE-YYYY-ID` regex; no match → fallback to vendor drill-down. Recent lookup chips stored in `localStorage`. |
| `/cves/:cveId` | CVE Detail | Summary, assigner, dates, severity badges (color-coded), CWES (clickable → CWE view), CPE configurations (copyable), references (external links). |
| `/vendors` | Vendors | Vendor list + search box (`/vendors/search`). Select vendor → `/vendors/:vendor`. |
| `/vendors/:vendor` | Products of vendor | Product list; select product → `/cves` filtered. |
| `/cves` (query-param driven) | CVE List | Dataset: vendor + product, page size, page, sort field (published/modified), direction. Shows total count (`/count` endpoint) and paginates. |

### CVE List page detail — pagination sorted by date

The main browsing page lists CVEs for a vendor+product, paginated and sorted **by date**:

- **Sort field** is either *published* or *modified* date (maps to the API's
  `descending`/`byPublished` path params: `byPublished=true` sorts by `Published`,
  otherwise by `Modified`; `descending=true` orders newest first, `descending=false`
  oldest first). Default: **newest published first** (`byPublished=true`, `descending=true`).
- **Page size** (`count`) is bounded — a small select (10 / 25 / 50 / 100), default 25,
  and always ≥ 1 to satisfy the API's validation.
- **Page control** (`page`) is ≥ 1, driven by the `page` query parameter. The paginator
  shows current page, total pages, and total items (from `GET
  /cve/search/{vendor}/{product}/count` → `{ total }`); total is refetched whenever the
  vendor/product changes, not per page turn.
- **State in URL**: `page`, `count`, `sort=published|modified`, and `direction=desc|asc`
  are query parameters — refresh, back/forward, and deep-links all restore the exact view.
- **Tie-in**: the sort toggle re-uses the same page if it still exists, else clamps to the
  last available page (a date re-sort can shrink the result set mid-browse).
| `/cwe/:id` | CWE Detail | Business rule/description from `CweViewModel`. |
| `/capec/:id` | CAPEC Detail | Attack pattern info from `CapecViewModel`. |

State: URL is source of truth for vendor/product/page/sort (slides on refresh + deep-linking).
No global state library — Angular signals + services only (YAGNI).

## 5. Components / services plan

- `core/services/api/` — one typed client per controller (`CveApi`, `VendorsApi`, `CweApi`, `CapecApi`), `HttpResource`-backed, mapping `{ total }` and 404s to `ResourceStatus`.
- Components: `SearchBar`, `CveCard` (list row), `SeverityBadge` (CVSS → color + label), `Paginator`, `CveDetail`, `VendorList`, `ProductList`, `CweDetail`, `CapecDetail`, shared `PageHeader`, `CopyButton`.
- Interceptor: attach base URL, normalize 404 → typed `NotFound` state (no toast spam).
- Severity mapping: same thresholds as NVD (Low `<4`, Medium `<7`, High `<8.5`? — CVSS3: Low `<4`, Medium `<7`, High `<9`, Critical `=10` in CVSS2 vs CVSS3 `≥ 9.0`). Spec pins CVSS3 thresholds: Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low > 0, None = 0. **Verify against domain conventions before implementation.**

## 6. Backend change (the only API-side edit)

`Web/Cve.Net.Search.Web/appsettings.json`:

```json
"Cors": {
  "Origins": [ "http://localhost:4200" ]
}
```

(The `CveUi` policy exists but is only registered when this section is non-empty.)
Prod origins to be appended by deployment; not hardcoded here.

## 7. Non-goals

- No comment, favorite, or tagging features.
- No GraphQL UI migration (keep REST; GraphQL is out of scope for v1).
- No authentication in the UI (API endpoints are public).
- No mobile/offline PWA.

## 8. Open questions → resolutions

1. ~~Dev API port~~ — **Resolved**: `http://localhost:5254` (launchSettings `applicationUrl`), reflected in the Angular dev environment.
2. ~~CVSS threshold table~~ — **Resolved** (ticket #9): backend ships severity strings (`CvssTwo.Severity` / `CvssThree.BaseSeverity`, NVD-imported); UI canonicalizes them and falls back to CVSS3 thresholds (None=0, Low<4, Medium<7, High<9, Critical≥9) or CVSS2 banding (no Critical tier) when the string is missing.
3. ~~Recent lookups persistence~~ — **Resolved** (ticket #10): local-only via localStorage (`cveui.recentLookups`, capped at 5); no backend changes.
4. ~~Vendor product list size~~ — **Resolved** (ticket #6): client-side filter box over the unpaginated vendor payload; server-backed autocomplete handles vendor discovery.
