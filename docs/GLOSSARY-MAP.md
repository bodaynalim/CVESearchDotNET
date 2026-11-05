# Glossary Map

## Contexts

- [CVE Search API](./GLOSSARY.md): the .NET REST service over the MongoDB CVE/CWE/CAPEC collections, including the recurring NVD/CAPEC imports that feed it
- [CveUI](../CveUI/GLOSSARY.md): the Angular SPA that browses and looks up the API's data; a read-only consumer

## Relationships

- **CveUI → CVE Search API**: CveUI consumes the REST endpoints read-only; it never writes and persists nothing server-side (recent lookups are browser-local)
- **Shared contract**: the API's JSON payload casing (camelCase) is agreed with CveUI; see ADR 0001 on the API side, ADR 0001 on the CveUI side
