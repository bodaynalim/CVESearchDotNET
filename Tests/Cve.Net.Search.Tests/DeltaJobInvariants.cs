using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Pure data-quality invariant checks for the MongoDB CVE delta jobs
/// (LoadCurrentDayCves / LoadNewAndModifiedPerHourCves). Every check returns the
/// names of the violated invariants — an empty result means the batch is sound.
/// Deliberately violating a fixture therefore fails the test with the invariant's
/// name (T12 verifiable outcome). No Mongo connection is involved: the checks are
/// pure functions over the flushed batches.
/// </summary>
public static class DeltaJobInvariants
{
    public const string IdsNonEmptyAndUniqueWithinBatch = "IdsNonEmptyAndUniqueWithinBatch";

    public const string DeduplicationAsDesigned = "DeduplicationAsDesigned";

    public const string ModificationDatesMonotonic = "ModificationDatesMonotonic";

    public const string DeltaSizeSane = "DeltaSizeSane";

    /// <summary>
    /// Mirrors CveBatchSize in VulnerabilitiesJsonHelper: a single flush may never
    /// exceed it (that would mean the batching boundary broke) and may never be empty
    /// (an empty delta is a failure, not a silent ok).
    /// </summary>
    public const int MaxCveBatchSize = 1000;

    /// <summary>
    /// Runs every applicable invariant over one flushed CVE batch.
    /// </summary>
    /// <param name="batch">The batch the job is about to hand to ICveMongoService.</param>
    /// <param name="storedModifiedByCveId">
    /// Last modification date per CveId already stored before this delta run; omit to
    /// skip the monotonicity check (e.g. an empty database).
    /// </param>
    public static IReadOnlyList<string> CheckCveBatch(
        IList<CveMongoModel>? batch,
        IReadOnlyDictionary<string, DateTime>? storedModifiedByCveId = null)
    {
        var violations = new List<string>();

        violations.AddRange(CheckDeltaSize(batch));

        if (batch is not { Count: > 0 })
            return violations;

        if (batch.Any(item => string.IsNullOrWhiteSpace(item.CveId))
            || batch.Select(item => item.CveId).Distinct().Count() != batch.Count)
            violations.Add(IdsNonEmptyAndUniqueWithinBatch);

        violations.AddRange(CheckDeduplication(batch));

        if (storedModifiedByCveId is not null)
            violations.AddRange(CheckModificationDates(batch, storedModifiedByCveId));

        return violations;
    }

    /// <summary>
    /// A flushed batch must have a non-empty, batch-unique id on every item.
    /// </summary>
    public static IReadOnlyList<string> CheckIds(IList<CveMongoModel>? batch)
    {
        if (batch is not { Count: > 0 })
            return Array.Empty<string>();

        var ids = batch.Select(item => item.CveId).ToList();

        return ids.Any(id => string.IsNullOrWhiteSpace(id)) || ids.Distinct().Count() != ids.Count
            ? new[] { IdsNonEmptyAndUniqueWithinBatch }
            : Array.Empty<string>();
    }

    /// <summary>
    /// The designed CVE deduplication is keep-first by CveId inside the Mongo service:
    /// a batch that still carries duplicate CveIds means the dedup did not run as designed.
    /// </summary>
    public static IReadOnlyList<string> CheckDeduplication(IList<CveMongoModel>? batch)
    {
        if (batch is not { Count: > 0 })
            return Array.Empty<string>();

        return batch.Select(item => item.CveId).Distinct().Count() == batch.Count
            ? Array.Empty<string>()
            : new[] { DeduplicationAsDesigned };
    }

    /// <summary>
    /// The designed vendor deduplication is one entry per vendor with a distinct
    /// software set (VulnerabilitiesJsonHelper collapses vendor/product pairs with
    /// HashSets before the bulk upsert).
    /// </summary>
    public static IReadOnlyList<string> CheckDeduplication(
        IList<(string Vendor, IReadOnlyList<string> Softwares)> vendorProducts)
    {
        var vendorsDeduplicated = vendorProducts.Select(vp => vp.Vendor).Distinct().Count() == vendorProducts.Count;
        var softwaresDeduplicated = vendorProducts.All(vp => vp.Softwares.Distinct().Count() == vp.Softwares.Count);

        return vendorsDeduplicated && softwaresDeduplicated
            ? Array.Empty<string>()
            : new[] { DeduplicationAsDesigned };
    }

    /// <summary>
    /// Modification dates may never move backwards: an incoming delta for a known
    /// CveId must carry a date that is equal to or newer than the stored one.
    /// </summary>
    public static IReadOnlyList<string> CheckModificationDates(
        IList<CveMongoModel>? batch,
        IReadOnlyDictionary<string, DateTime> storedModifiedByCveId)
    {
        if (batch is not { Count: > 0 })
            return Array.Empty<string>();

        var movesBackwards = batch.Any(item =>
            storedModifiedByCveId.TryGetValue(item.CveId, out var stored)
            && item.Modified < stored);

        return movesBackwards
            ? new[] { ModificationDatesMonotonic }
            : Array.Empty<string>();
    }

    /// <summary>
    /// Delta size sanity: an empty flush and an unbounded flush are both failures,
    /// never a silent ok.
    /// </summary>
    public static IReadOnlyList<string> CheckDeltaSize(IList<CveMongoModel>? batch)
    {
        return batch is not { Count: > 0 } || batch.Count > MaxCveBatchSize
            ? new[] { DeltaSizeSane }
            : Array.Empty<string>();
    }
}
