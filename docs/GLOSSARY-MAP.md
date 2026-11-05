# Glossary Map

## Contexts

- [CVE Search API](./GLOSSARY.md): the .NET REST service over the MongoDB CVE/CWE/CAPEC collections, including the recurring NVD/CAPEC imports that feed it
- [CveUI](../CveUI/GLOSSARY.md): the Angular SPA that browses and looks up the API's data; a read-only consumer

## Relationships

- **CveUI → CVE Search API**: CveUI consumes the REST endpoints read-only; it never writes and persists nothing server-side (recent lookups are browser-local). Both contexts' URL and listing conventions are recorded UI-side: `CveUI/docs/adr/0001` (single HTTP test seam) and `CveUI/docs/adr/0002` (URL-as-source-of-truth list contract).
- **Shared contract**: the API's JSON payload casing (wire = camelCase) is the single authoritative record for both sides (see `docs/adr/0001-api-json-contract-is-camelCase.md`); one decision, one record.
