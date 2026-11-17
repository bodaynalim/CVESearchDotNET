using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Fixture-driven invariant verdicts at the flush contract: each named fixture under
/// Fixtures/batches holds a batch exactly as the delta job hands it to
/// ICveMongoService (CVE batches) or IVendorMongoService (vendor aggregations),
/// together with its expectedInvariantViolations. A positive fixture must produce a
/// clean verdict; a violating fixture must fail with the invariant's name — never
/// silently. The checker is the observation point for the invariant semantics.
/// </summary>
public class DeltaJobInvariantsTests
{
    public static TheoryData<string> PositiveBatchFixtures()
    {
        return BatchFixtures(expectedViolations: false);
    }

    public static TheoryData<string> ViolatingBatchFixtures()
    {
        return BatchFixtures(expectedViolations: true);
    }

    private static TheoryData<string> BatchFixtures(bool expectedViolations)
    {
        var data = new TheoryData<string>();

        foreach (var name in DeltaJobFixtures.BatchFixtureNames())
        {
            if (DeltaJobFixtures.ReadBatch(name).ExpectedInvariantViolations.Count > 0 == expectedViolations)
                data.Add(name);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(PositiveBatchFixtures))]
    public void FlushContractBatch_WithPositiveFixture_ReportsNoInvariantViolations(string fixtureName)
    {
        var fixture = DeltaJobFixtures.ReadBatch(fixtureName);

        var violations = EvaluateBatchFixture(fixture);

        violations.Should().BeEmpty(
            "fixture {0} documents a sound batch: {1}", fixtureName, fixture.Description);
    }

    [Theory]
    [MemberData(nameof(ViolatingBatchFixtures))]
    public void FlushContractBatch_WithViolatingFixture_FailsWithTheNamedInvariants(string fixtureName)
    {
        var fixture = DeltaJobFixtures.ReadBatch(fixtureName);

        var violations = EvaluateBatchFixture(fixture);

        violations.Should().Equal(fixture.ExpectedInvariantViolations,
            "fixture {0} documents a deliberate violation: {1}", fixtureName, fixture.Description);
    }

    private static List<string> EvaluateBatchFixture(DeltaBatchFixture fixture)
    {
        var violations = new List<string>();

        if (fixture.Cves.Count > 0)
        {
            var batch = fixture.Cves
                .Select(cve => new CveMongoModel { CveId = cve.CveId, Modified = cve.Modified })
                .ToList();

            violations.AddRange(DeltaJobInvariants.CheckCveBatch(batch, fixture.StoredModified));
        }
        else if (fixture.VendorProducts.Count == 0)
        {
            // No batch was flushed: the observed batch at the flush contract is empty,
            // and an empty delta is a size failure, not a silent ok.
            violations.AddRange(DeltaJobInvariants.CheckDeltaSize(new List<CveMongoModel>()));
        }

        if (fixture.VendorProducts.Count > 0)
        {
            var vendorProducts = fixture.VendorProducts
                .Select(vp => (vp.Vendor, (IReadOnlyList<string>)vp.Softwares))
                .ToList();

            violations.AddRange(DeltaJobInvariants.CheckDeduplication(vendorProducts));
        }

        return violations.Distinct().ToList();
    }
}
