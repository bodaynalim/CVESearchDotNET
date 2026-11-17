using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Pure invariant tests for the delta-job data-quality checks (T12). Each invariant
/// has a positive case (sound batch → no violations) and a negative case (a
/// deliberately violating fixture → the test fails naming the invariant).
/// </summary>
public class DeltaJobInvariantsTests
{
    private static readonly DateTime DefaultModified = new(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc);

    private static CveMongoModel Cve(string cveId, DateTime? modified = null)
    {
        return new CveMongoModel
        {
            CveId = cveId,
            Modified = modified ?? DefaultModified
        };
    }

    #region Ids non-empty and unique within a batch

    [Fact]
    public void CheckCveBatch_WithDistinctNonEmptyIds_ReportsNoViolations()
    {
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001"), Cve("CVE-2026-0002") };

        DeltaJobInvariants.CheckCveBatch(batch).Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void CheckCveBatch_WithBlankCveId_FailsWithIdsInvariantName(string? cveId)
    {
        // The null id is the point of this negative case, hence the suppression.
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001"), Cve(cveId!) };

        DeltaJobInvariants.CheckCveBatch(batch)
            .Should().Contain(DeltaJobInvariants.IdsNonEmptyAndUniqueWithinBatch);
    }

    [Fact]
    public void CheckCveBatch_WithDuplicateCveIds_FailsWithIdsInvariantName()
    {
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001"), Cve("CVE-2026-0001") };

        DeltaJobInvariants.CheckCveBatch(batch)
            .Should().Contain(DeltaJobInvariants.IdsNonEmptyAndUniqueWithinBatch);
    }

    #endregion

    #region Deduplication behaves as designed

    [Fact]
    public void CheckCveBatch_WithKeepFirstDedupApplied_ReportsNoViolations()
    {
        // A batch where the designed keep-first dedup has already collapsed duplicates.
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001"), Cve("CVE-2026-0002") };

        DeltaJobInvariants.CheckCveBatch(batch)
            .Should().NotContain(DeltaJobInvariants.DeduplicationAsDesigned);
    }

    [Fact]
    public void CheckCveBatch_WithDuplicateCveIds_FailsWithDedupInvariantName()
    {
        // Two occurrences of the same CveId survived into a flushed batch: the
        // designed keep-first dedup did not run.
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001"), Cve("CVE-2026-0001") };

        DeltaJobInvariants.CheckCveBatch(batch)
            .Should().Contain(DeltaJobInvariants.DeduplicationAsDesigned);
    }

    [Fact]
    public void CheckDeduplication_WithCollapsedVendorProducts_ReportsNoViolations()
    {
        // One entry per vendor, distinct software sets (the designed vendor aggregation).
        var vendorProducts = new List<(string Vendor, IReadOnlyList<string> Softwares)>
        {
            ("acme", new[] { "gadget", "widget" }),
            ("beta", new[] { "gadget" })
        };

        DeltaJobInvariants.CheckDeduplication(vendorProducts).Should().BeEmpty();
    }

    [Fact]
    public void CheckDeduplication_WithDuplicateVendorEntries_FailsWithDedupInvariantName()
    {
        var vendorProducts = new List<(string Vendor, IReadOnlyList<string> Softwares)>
        {
            ("acme", new[] { "widget" }),
            ("acme", new[] { "gadget" })
        };

        DeltaJobInvariants.CheckDeduplication(vendorProducts)
            .Should().Contain(DeltaJobInvariants.DeduplicationAsDesigned);
    }

    [Fact]
    public void CheckDeduplication_WithDuplicateSoftwaresWithinVendor_FailsWithDedupInvariantName()
    {
        var vendorProducts = new List<(string Vendor, IReadOnlyList<string> Softwares)>
        {
            ("acme", new[] { "widget", "widget" })
        };

        DeltaJobInvariants.CheckDeduplication(vendorProducts)
            .Should().Contain(DeltaJobInvariants.DeduplicationAsDesigned);
    }

    #endregion

    #region Modification dates monotonic (never move backwards)

    [Fact]
    public void CheckModificationDates_WhenIncomingDateIsUnchangedOrNewer_ReportsNoViolations()
    {
        var stored = new Dictionary<string, DateTime> { ["CVE-2026-0001"] = DefaultModified };
        var batch = new List<CveMongoModel>
        {
            Cve("CVE-2026-0001", DefaultModified),                                // unchanged
            Cve("CVE-2026-0002", DefaultModified.AddDays(1))                      // brand new, forward
        };

        DeltaJobInvariants.CheckModificationDates(batch, stored).Should().BeEmpty();
    }

    [Fact]
    public void CheckModificationDates_WhenIncomingDateIsOlder_FailsWithMonotonicInvariantName()
    {
        var stored = new Dictionary<string, DateTime> { ["CVE-2026-0001"] = DefaultModified };
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001", DefaultModified.AddDays(-1)) };

        DeltaJobInvariants.CheckModificationDates(batch, stored)
            .Should().Contain(DeltaJobInvariants.ModificationDatesMonotonic);
    }

    [Fact]
    public void CheckCveBatch_WithStoredStateAndOlderDate_FailsWithMonotonicInvariantName()
    {
        var stored = new Dictionary<string, DateTime> { ["CVE-2026-0001"] = DefaultModified.AddDays(1) };
        var batch = new List<CveMongoModel> { Cve("CVE-2026-0001") };

        DeltaJobInvariants.CheckCveBatch(batch, stored)
            .Should().Contain(DeltaJobInvariants.ModificationDatesMonotonic);
    }

    #endregion

    #region Delta size sane (empty/unbounded are failures, not silent ok)

    [Fact]
    public void CheckDeltaSize_WithNonEmptyBoundedBatch_ReportsNoViolations()
    {
        var batch = new List<CveMongoModel>(Enumerable.Range(1, DeltaJobInvariants.MaxCveBatchSize)
            .Select(i => Cve($"CVE-2026-{i:D4}")));

        DeltaJobInvariants.CheckDeltaSize(batch).Should().BeEmpty();
    }

    [Fact]
    public void CheckDeltaSize_WithEmptyBatch_FailsWithSizeInvariantName()
    {
        DeltaJobInvariants.CheckDeltaSize(new List<CveMongoModel>())
            .Should().Contain(DeltaJobInvariants.DeltaSizeSane);
    }

    [Fact]
    public void CheckDeltaSize_WithOversizedBatch_FailsWithSizeInvariantName()
    {
        var batch = new List<CveMongoModel>(Enumerable.Range(1, DeltaJobInvariants.MaxCveBatchSize + 1)
            .Select(i => Cve($"CVE-2026-{i:D4}")));

        DeltaJobInvariants.CheckDeltaSize(batch)
            .Should().Contain(DeltaJobInvariants.DeltaSizeSane);
    }

    #endregion
}
