# Glossary

| Term | Definition |
| --- | --- |
| Vulnerabilities page | The app's default view (`/cves`): paginated CVE list, optionally scoped by vendor/product, optionally filtered by a keyword in the CVE ID or description. |
| CVE lookup | Looking up a single CVE by exact ID; available from the lookup card on the Vulnerabilities page. Records locally to recent lookups. |
| Global CVE search | Browsing all CVEs without a vendor/product scope; result table plus pagination and date sorting. |
| Weaknesses page | The CWE list page (`/cwe`) under the Weaknesses navigation entry: paginated CWE entries in ascending numeric-ID order with keyword search on ID or name. |
| CWE entry | A CWE enumeration entry identified by a numeric ID, e.g. 79 (Cross-site Scripting). URLs use the bare numeric ID. |
| Keyword | A single submitted search phrase matching as a case-insensitive substring. |
| Result set | The complete set of entries behind a listing (CVE or CWE): one count request serves every pagination page turn for the same result set. |
| Severity | A CVSS-derived classification (None, Low, Medium, High, Critical) rendered as a badge; CVSS3 preferred over CVSS2; entries without scores display "Not scored". |
| Recent lookups | The last five successfully opened CVE IDs, kept only in the browser's local storage. |
