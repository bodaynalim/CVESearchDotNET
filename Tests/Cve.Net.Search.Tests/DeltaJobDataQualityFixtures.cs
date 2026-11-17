using System.Security.Cryptography;
using System.Text;

namespace Cve.Net.Search.Tests;

/// <summary>
/// In-memory input→output fixtures for the MongoDB CVE delta jobs
/// (LoadCurrentDayCves / LoadNewAndModifiedPerHourCves). Per AGENTS.md §2 live Mongo
/// state is never a fixture: every payload here is an NVD 2.0 delta feed in the exact
/// shape the jobs fetch, and the expected output is documented next to each payload —
/// the batches the job must hand to ICveMongoService.CreateOrUpdateExisting and
/// IVendorMongoService.BulkUpsertVendors.
/// </summary>
public static class DeltaJobDataQualityFixtures
{
    public const string EmptyDeltaPayload = "[]";

    public const string SourceIdentifier = "test@unit.test";

    public const string FirstCveId = "CVE-2026-0001";

    public const string SecondCveId = "CVE-2026-0002";

    public const string FirstCveModified = "2026-02-01T00:00:00Z";

    public const string SecondCveModified = "2026-02-02T00:00:00Z";

    /// <summary>
    /// Two distinct CVEs sharing the vendor "acme" (overlapping products) plus vendor
    /// "beta". Expected output: one flushed batch of two CVEs with non-empty unique
    /// ids and the feed's modification dates, and one vendor upsert with
    /// { acme: [gadget, widget], beta: [gadget] } — duplicates collapsed.
    /// </summary>
    public static string BuildValidDeltaPayload()
    {
        return BuildDeltaPayload(
            BuildCve(FirstCveId, "2026-01-01T00:00:00Z", FirstCveModified, ("acme", "widget")),
            BuildCve(SecondCveId, "2026-01-02T00:00:00Z", SecondCveModified, ("acme", "gadget"), ("beta", "gadget")));
    }

    /// <summary>
    /// The same CveId delivered twice within one delta feed (ids invariant violation).
    /// Expected output: one flushed batch of two items, both carrying the duplicate id.
    /// </summary>
    public static string BuildDuplicateIdDeltaPayload()
    {
        return BuildDeltaPayload(
            BuildCve(FirstCveId, "2026-01-01T00:00:00Z", FirstCveModified, ("acme", "widget")),
            BuildCve(FirstCveId, "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", ("acme", "widget")));
    }

    /// <summary>
    /// A single-CVE delta feed with the given lastModified date — used to simulate
    /// consecutive delta runs of the same CVE (monotonicity fixture).
    /// </summary>
    public static string BuildSingleCveDeltaPayload(string cveId, string lastModified)
    {
        return BuildDeltaPayload(
            BuildCve(cveId, "2026-01-01T00:00:00Z", lastModified, ("acme", "widget")));
    }

    /// <summary>
    /// A delta feed with exactly <paramref name="count"/> distinct CVEs
    /// (CVE-2026-0001 … CVE-2026-{count:D4}), one vendor each — used to exercise the
    /// batch-size flush boundary.
    /// </summary>
    public static string BuildSizedDeltaPayload(int count)
    {
        var items = new List<string>(count);

        for (var i = 1; i <= count; i++)
            items.Add(BuildCve($"CVE-2026-{i:D4}", "2026-01-01T00:00:00Z", SecondCveModified, ($"vendor-{i:D4}", "product")));

        return BuildDeltaPayload(items.ToArray());
    }

    /// <summary>
    /// Parses an NVD-style RFC 3339 timestamp the way the delta mapping stores it
    /// (UTC instant), so fixtures can express expected output dates.
    /// </summary>
    public static DateTime ParseTimestamp(string timestamp)
    {
        return DateTime.Parse(timestamp, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
    }

    private static string BuildDeltaPayload(params string[] cveItems)
    {
        return "[" + string.Join(",", cveItems) + "]";
    }

    private static string BuildCve(string cveId, string published, string lastModified,
        params (string Vendor, string Product)[] cpes)
    {
        var cpeMatches = cpes
            .Select(cpe =>
            {
                var criteria = $"cpe:2.3:a:{cpe.Vendor}:{cpe.Product}:1.0:*:*:*:*:*:*:*";

                return $$"""
                    { "vulnerable": true, "matchCriteriaId": "{{BuildCriteriaGuid(criteria)}}", "criteria": "{{criteria}}" }
                    """;
            })
            .ToList();

        return $$"""
            {
              "cve": {
                "id": "{{cveId}}",
                "sourceIdentifier": "{{SourceIdentifier}}",
                "published": "{{published}}",
                "lastModified": "{{lastModified}}",
                "descriptions": [ { "lang": "en", "value": "Summary of {{cveId}}" } ],
                "references": [],
                "metrics": {},
                "weaknesses": [],
                "configurations": [
                  {
                    "nodes": [
                      { "operator": "OR", "negate": false, "cpeMatch": [ {{string.Join(", ", cpeMatches)}} ] }
                    ]
                  }
                ]
              }
            }
            """;
    }

    private static string BuildCriteriaGuid(string criteria)
    {
        return new Guid(MD5.HashData(Encoding.UTF8.GetBytes(criteria))).ToString();
    }
}
