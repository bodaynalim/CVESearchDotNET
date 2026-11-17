using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Golden dataset for keyword search (ticket T02, semantics per ADR-0002: one phrase,
/// case-insensitive substring match against CveId and Summary).
/// Expected results are hand-written, not generated from the current filter code.
/// </summary>
public static class KeywordGoldenDataset
{
    /// <summary>One CVE record of the fixture; only the searched fields carry data.</summary>
    public sealed record GoldenCve(string CveId, string Summary);

    /// <summary>One golden search: the phrase a user would type and the exact CVE IDs it must return.</summary>
    public sealed record GoldenCase(string Keyword, IReadOnlyList<string> ExpectedCveIds, string Why);

    /// <summary>A phrase that must return nothing — the negative half of the contract.</summary>
    public sealed record GoldenNegativeCase(string Keyword, string Why);

    public static IReadOnlyList<GoldenCve> Records { get; } =
    [
        new("CVE-2019-0001",
            "Stack overflow in the parser of Acme Widget Server allows remote attackers to cause a denial of service."),
        new("CVE-2019-0002", "Heap overflow in acme image decoder leads to remote code execution."),
        new("CVE-2019-0003", "Buffer overflow in the XYZ compression library corrupts heap memory."),
        new("CVE-2019-0004", "Integer overflow in acme calc causes an incorrect total price."),
        new("CVE-2020-1111", "SQL injection in the admin dashboard of Beta CMS exposes customer records."),
        new("CVE-2020-2222", "Cross-site scripting (XSS) in the comment form of beta portal."),
        new("CVE-2020-3333", "Path traversal in the file uploader of Beta CMS allows reading arbitrary files."),
        new("CVE-2020-4444", "Use-after-free in the PDF renderer of Beta CMS crashes the server."),
        new("CVE-2021-1001", "ACME-Cloud Sync version 2.4.1 leaks synchronization credentials in logs."),
        new("CVE-2021-1002", "The Beta-Logger component writes plaintext passwords; CVE-2021-1002 was reported by vendor ACME."),
        new("CVE-2021-1003", "Path traversal (../../etc/passwd) in acme-file-utils 1.0.3."),
        new("CVE-2021-2001", "acme.widget.server 3.1.0 allows SSRF via the proxy settings page."),
        new("CVE-2021-2002", "beta.cms 9.0 stores session tokens in URLs, enabling token theft via referrer headers."),
        new("CVE-2022-5000", "The CVE-2022-5000 parser mishandles hyphenated-product-names such as ACME-Widget-X."),
        new("CVE-2022-5001", "Double free in gamma.crypto library 0.9 allows heap corruption."),
        new("CVE-2022-5002", "Open redirect in the beta portal login?next= parameter."),
        new("CVE-2022-5003", "Deserialization of untrusted data in acme-batch-importer runs arbitrary code."),
        new("CVE-2022-6001", "Unquoted search path in the ACME Agent Windows service allows privilege escalation."),
        new("CVE-2023-7001", "XXE in the beta-doc-converter XML parser discloses local files."),
        new("CVE-2023-7002", "Weak password requirements in the acme admin panel allow brute-force attacks."),
        new("CVE-2023-7003", "The BETA-Reporting module leaks stack traces to end users."),
        new("CVE-2023-7004", "Missing authorization in gamma.test-framework runner (CVE-2023-7003 follow-up) allows arbitrary file write."),
        new("CVE-2018-0999", "Information exposure in acme-backup-tool configuration dump reveals database credentials."),
        new("CVE-2018-0998", "The beta-timezone helper prints wrong UTC offsets for historical dates."),
    ];

    /// <summary>
    /// Positive golden cases. "Multiple keywords" in the ticket means a single typed
    /// phrase containing several words — per ADR-0002 it is matched as one contiguous substring.
    /// </summary>
    public static IReadOnlyList<GoldenCase> Cases { get; } =
    [
        // Exact match — the full CVE id as typed.
        new("CVE-2019-0001", ["CVE-2019-0001"], "exact full-id match"),
        // Case insensitivity (ADR-0002) in both directions.
        new("cve-2019-0001", ["CVE-2019-0001"], "lowercase id matches uppercase-stored id"),
        new("SQL INJECTION", ["CVE-2020-1111"], "uppercase phrase matches lowercase-stored summary"),
        new("(XSS)", ["CVE-2020-2222"], "regex metacharacters are matched literally"),
        new("CVE-2023-7001", ["CVE-2023-7001"], "uppercase stored text is found by its exact casing too"),
        // Substring in the middle of a term.
        new("overflow", ["CVE-2019-0001", "CVE-2019-0002", "CVE-2019-0003", "CVE-2019-0004"], "substring in the middle of a word"),
        new("ender", ["CVE-2020-4444"], "substring from the middle of the word 'renderer'"),
        // Separators and special characters.
        new("acme-batch", ["CVE-2022-5003"], "hyphen inside the searched text"),
        new("ACME-Widget", ["CVE-2022-5000"], "hyphen, case-insensitive against mixed-case stored text"),
        new("2.4.1", ["CVE-2021-1001"], "dots in a version number"),
        new("3.1.0", ["CVE-2021-2001"], "dots in a version number, other record"),
        new("1.0.3", ["CVE-2021-1003"], "version number at the end of the summary"),
        new("login?next=", ["CVE-2022-5002"], "query-string characters survive regex escaping"),
        // CVE-id format pieces.
        new("2021-100", ["CVE-2021-1001", "CVE-2021-1002", "CVE-2021-1003"], "year-sequence fragment hits all three ids"),
        new("099", ["CVE-2018-0999", "CVE-2018-0998"], "numeric fragment shared by two ids"),
        new("CVE-2021-1001", ["CVE-2021-1001"], "exact full-id match, another record"),
        // Multiple keywords at once — one contiguous phrase, per ADR-0002.
        new("stack overflow", ["CVE-2019-0001"], "two-word phrase matches only where it is contiguous"),
        new("double free", ["CVE-2022-5001"], "two-word phrase, another record"),
        new("denial of service", ["CVE-2019-0001"], "three-word phrase"),
        new("the",
            ["CVE-2019-0001", "CVE-2019-0003", "CVE-2020-1111", "CVE-2020-2222", "CVE-2020-3333",
             "CVE-2020-4444", "CVE-2021-1002", "CVE-2021-2001", "CVE-2021-2002", "CVE-2022-5000",
             "CVE-2022-5002", "CVE-2022-6001", "CVE-2023-7001", "CVE-2023-7002", "CVE-2023-7003",
             "CVE-2018-0998"],
            "single word hits many records via summary (substring rules count, e.g. 'theft')"),
        // Cross-field: the same keyword hits CveId on some records and Summary on others.
        new("CVE-2023-7003", ["CVE-2023-7003", "CVE-2023-7004"], "id string matches one record's id and another record's summary"),
        new("7003", ["CVE-2023-7003", "CVE-2023-7004"], "fragment matches id of one record and summary of another"),
        new("beta", ["CVE-2020-1111", "CVE-2020-2222", "CVE-2020-3333", "CVE-2020-4444", "CVE-2021-1002",
                     "CVE-2021-2002", "CVE-2022-5002", "CVE-2023-7001", "CVE-2023-7003", "CVE-2018-0998"],
            "vendor name matches via summaries across many records"),
    ];

    public static IReadOnlyList<GoldenNegativeCase> NegativeCases { get; } =
    [
        new("nginx", "popular product that never appears in the fixture"),
        new("ransomware", "vulnerability class absent from the fixture"),
        new("CVE-1999-0001", "well-formed id of a record that is not in the fixture"),
        new("openssl", "product name similar in shape to fixture names but absent"),
        new("beta-cms", "hyphenated product variant that does not exist (records write 'Beta CMS')"),
        new("9999", "year fragment no record carries"),
    ];
}
