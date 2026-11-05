/**
 * Path-segment encoding for route-per-segment endpoints.
 * Vendor/product names may contain `/`, which the API sends as `%2F` in the
 * URL path and replaces back server-side. This is the ONLY place that
 * encodes path segments, so it never leaks into components.
 *
 * Known limitation (inherited from the backend's literal `%2F` → `/`
 * replacement after path decoding): a vendor/product literally named
 * `x%2Fy` would be indistinguishable from `x/y`. CVE/CWE/CAPEC identifiers
 * are safe (dash/digit-only).
 */
export function encodePathSegment(value: string | number): string {
  return encodeURIComponent(String(value));
}
