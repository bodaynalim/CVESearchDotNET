# Keyword search is case-insensitive substring matching, not full-text

List and count endpoints match the search phrase as a case-insensitive regex substring across a deliberately small field set (CVE: `CveId` + `Summary`; CWE: `CweId` + `Name`), built by a shared regex-filter builder. The phrase is what the user typed in once — no ranking, no boolean operators, no field-specific syntax.

This was chosen over a Mongo text index or external search because the requirement is point-lookups and eyeball-browsable lists over bounded datasets (CVEs are always scoped or one keyword; CWE is ~1.5k docs), the regex stays index-cheap on ID prefixes for drill-down, and ranking complexity was explicitly out of scope. A future full-text need does not invalidate this contract: the routes and semantics stay, ranking would be additive.

Consequence: relevance ordering does not exist; a keyword that matches thousands of CVEs yields the same simple date/id-ordered pagination as an empty scope.
