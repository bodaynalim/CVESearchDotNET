# CVE Search API

The .NET REST service exposing the vulnerability database collected from NVD, CWE and CAPEC sources into MongoDB. The domain's nouns are three vulnerability-😅-related enumerations and their relations.

## Language

### Database substances

**CVE entry**:
A single CVE document identified by its CVE ID (e.g. CVE-2018-0001); carries dates, a summary, CVSS scores and the affected software chains.
_Avoid_: vulnerability record, cve item

**CWE entry**:
A weakness-class enumeration entry identified by a numeric ID (e.g. 79); CVEs reference weakness classes through CWE entries.
_Avoid_: weakness, cwe

**CAPEC entry**:
An attack-pattern enumeration entry identified by a numeric ID; related to CWE entries through chains.

**Vendor product pair**:
A vendor together with one of its affected products; a CVE lists software chains, and vendor→product is how users drill down into the CVE collection.

### Search

**Keyword**:
A single submitted search phrase matched as a case-insensitive substring against an entry's ID or its text fields.
_Avoid_: query, full-text search

### Ordering

**Severity (classification)**:
The NAD-CVSS-derived band (None, Low, Medium, High, Critical) attached to a CVE; CVSS3 bands include Critical, CVSS2 bands start from High.
_Avoid_: score (the numeric value), rating

**Origin (CWE)**:
Whether a CWE ID came from a CWE official list or from NVD's imported extensions; related-entry IDs may therefore be bare numerics or prefixed forms.

### Ingestion

**Initial import**:
The first-time population of the database from full year archives plus the current XML enumerations, run once and then tracked as completed steps.

**Delta import**:
The recurring hourly/daily refreshes that pull since-last-run changes from the NVD API so the database stays current.
