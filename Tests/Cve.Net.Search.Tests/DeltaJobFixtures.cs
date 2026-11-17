using System.Text.Json;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Loads the hand-authored T12 delta-job fixture pairs from
/// Tests/Cve.Net.Search.Tests/Fixtures (copied next to the test binaries).
/// - delta-jobs/{name}.input.json — the raw NVD 2.0 delta feed exactly as the job
///   fetches it (stubbed into the HTTP seam verbatim);
/// - delta-jobs/{name}.expected.json — the documented job output: the batches the
///   job must hand to ICveMongoService / IVendorMongoService and the invariant
///   verdict for those batches;
/// - batches/{name}.json — a batch as observed at the flush contract together with
///   its expected invariant verdict.
/// The test narrative is "this fixture input must produce this outcome".
/// </summary>
public static class DeltaJobFixtures
{
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "Fixtures");

    public static byte[] ReadDeltaInput(string name)
    {
        return File.ReadAllBytes(Path.Combine(Root, "delta-jobs", name + ".input.json"));
    }

    public static DeltaJobExpectedFixture ReadDeltaExpected(string name)
    {
        return Deserialize<DeltaJobExpectedFixture>(Path.Combine(Root, "delta-jobs", name + ".expected.json"));
    }

    public static DeltaBatchFixture ReadBatch(string name)
    {
        return Deserialize<DeltaBatchFixture>(Path.Combine(Root, "batches", name + ".json"));
    }

    public static IReadOnlyList<string> BatchFixtureNames()
    {
        return Directory.GetFiles(Path.Combine(Root, "batches"), "*.json")
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();
    }

    private static readonly JsonSerializerOptions FixtureJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static T Deserialize<T>(string path)
    {
        var json = File.ReadAllText(path);

        return JsonSerializer.Deserialize<T>(json, FixtureJsonOptions)
               ?? throw new InvalidOperationException($"Fixture {path} deserialized to null");
    }
}

/// <summary>
/// Expected output of one delta-job run, hand-authored next to its input feed.
/// </summary>
public sealed class DeltaJobExpectedFixture
{
    public string Description { get; set; } = string.Empty;

    public List<int> ExpectedCveBatchSizes { get; set; } = new();

    /// <summary>Per-batch CveIds in feed order; asserted when present.</summary>
    public List<List<string>>? ExpectedCveIdsByBatch { get; set; }

    /// <summary>Modification date per CveId over all flushed items; asserted when present.</summary>
    public Dictionary<string, DateTime>? ExpectedModifiedByCveId { get; set; }

    public List<List<FixtureVendorBatch>>? ExpectedVendorBatches { get; set; }

    /// <summary>Stored modification state this run is judged against (e.g. left by the previous delta run).</summary>
    public Dictionary<string, DateTime>? StoredModifiedByCveId { get; set; }

    public List<string> ExpectedInvariantViolations { get; set; } = new();
}

public sealed class FixtureVendorBatch
{
    public string Vendor { get; set; } = string.Empty;

    public List<string> Softwares { get; set; } = new();
}

/// <summary>
/// A batch as observed at the flush contract plus its expected invariant verdict.
/// </summary>
public sealed class DeltaBatchFixture
{
    public string Description { get; set; } = string.Empty;

    public List<FixtureCve> Cves { get; set; } = new();

    public List<FixtureVendorBatch> VendorProducts { get; set; } = new();

    public Dictionary<string, DateTime>? StoredModified { get; set; }

    public List<string> ExpectedInvariantViolations { get; set; } = new();
}

public sealed class FixtureCve
{
    public string CveId { get; set; } = string.Empty;

    public DateTime Modified { get; set; }
}
