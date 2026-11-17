using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Helpers;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Infrastructure.Configuration;
using FluentAssertions;
using Hangfire;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Fixture-driven delta-job tests over the same seam as
/// VulnerabilitiesJsonHelperInitialImportTests (T12): every test loads a named
/// fixture pair under Fixtures/delta-jobs — the input feed is served verbatim at the
/// stubbed HTTP seam, and the flushed batches are compared against the fixture's
/// documented expected output (batch sizes, ids, modification dates, vendor
/// aggregation) and invariant verdict. No Mongo connection is made (AGENTS.md §2);
/// the narrative is "this fixture input must produce this outcome".
/// </summary>
public class VulnerabilitiesJsonHelperDeltaJobTests
{
    private const string ModifiedApiPrefix = "https://unit.test/rest/json/cves/2.0/?lastModStartDate";

    private const string PublishedApiPrefix = "https://unit.test/rest/json/cves/2.0/?pubStartDate";

    private readonly ICveMongoService _cveMongoService = Substitute.For<ICveMongoService>();

    private readonly IVendorMongoService _vendorMongoService = Substitute.For<IVendorMongoService>();

    private readonly IHttpClientFactory _httpClientFactory = Substitute.For<IHttpClientFactory>();

    private readonly StubHttpHandler _httpHandler = new();

    private readonly List<IList<CveMongoModel>> _flushedCveBatches = new();

    private readonly List<IList<(string Vendor, IReadOnlyList<string> Softwares)>> _flushedVendorBatches = new();

    public VulnerabilitiesJsonHelperDeltaJobTests()
    {
        _cveMongoService
            .CreateOrUpdateExisting(
                Arg.Do<IList<CveMongoModel>>(_flushedCveBatches.Add), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _vendorMongoService
            .BulkUpsertVendors(
                Arg.Do<IList<(string Vendor, IReadOnlyList<string> Softwares)>>(_flushedVendorBatches.Add),
                Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _httpClientFactory.CreateClient().Returns(_ => new HttpClient(_httpHandler));

        // The published window returns an empty delta by default; each fixture pair is
        // served on the modified window.
        _httpHandler.RespondPrefix(PublishedApiPrefix, DeltaJobFixtures.ReadDeltaInput("empty-delta"));
    }

    #region Fixture: valid-delta — all four invariants hold

    [Fact]
    public async Task LoadCurrentDayCves_ValidDeltaFixture_ProducesExpectedFlushesWithoutInvariantViolations()
    {
        await RunDeltaAndVerify("valid-delta");
    }

    #endregion

    #region Fixture: duplicate-cve-id-delta — deliberate violation, named invariants

    [Fact]
    public async Task LoadCurrentDayCves_DuplicateCveIdFixture_FlushesBothAndFailsWithIdsAndDedupInvariantNames()
    {
        await RunDeltaAndVerify("duplicate-cve-id-delta");
    }

    #endregion

    #region Fixture: empty-delta — nothing flushed, size invariant names the failure

    [Fact]
    public async Task LoadCurrentDayCves_EmptyDeltaFixture_FlushesNothingAndFailsSizeInvariant()
    {
        await RunDeltaAndVerify("empty-delta");
    }

    #endregion

    #region Fixture pair: monotonic-run1 + monotonic-run2 — dates never move backwards

    [Fact]
    public async Task LoadCurrentDayCves_MonotonicFixturePair_WhenSecondRunMovesDateBackwards_FailsWithMonotonicInvariantName()
    {
        // Run 1 establishes the stored modification state documented in its fixture.
        await RunDeltaAndVerify("monotonic-run1");

        // Run 2 re-delivers the same CVE with an older modification date.
        await RunDeltaAndVerify("monotonic-run2-backwards");
    }

    [Fact]
    public async Task LoadCurrentDayCves_MonotonicFixturePair_WhenSecondRunDateIsUnchanged_ReportsNoViolations()
    {
        await RunDeltaAndVerify("monotonic-run1");

        // An unchanged modification date never moves backwards.
        await RunDeltaAndVerify("monotonic-run2-equal");
    }

    #endregion

    #region Fixture: oversized-delta — batching keeps every flush bounded

    [Fact]
    public async Task LoadCurrentDayCves_OversizedDeltaFixture_ProducesBoundedBatchesWithUniqueIds()
    {
        await RunDeltaAndVerify("oversized-delta");
    }

    #endregion

    /// <summary>
    /// Serves the fixture input on the modified-window seam, runs the delta job once,
    /// and verifies everything the job flushed against the fixture's expected output
    /// and invariant verdict.
    /// </summary>
    private async Task RunDeltaAndVerify(string fixtureName)
    {
        _flushedCveBatches.Clear();
        _flushedVendorBatches.Clear();

        _httpHandler.RespondPrefix(ModifiedApiPrefix, DeltaJobFixtures.ReadDeltaInput(fixtureName));

        var expected = DeltaJobFixtures.ReadDeltaExpected(fixtureName);

        await CreateHelper().LoadCurrentDayCves();

        VerifyFlushesAgainstExpected(fixtureName, expected);
    }

    private void VerifyFlushesAgainstExpected(string fixtureName, DeltaJobExpectedFixture expected)
    {
        VerifyCveFlushes(fixtureName, expected);
        VerifyVendorFlushes(fixtureName, expected);
        VerifyInvariantVerdict(fixtureName, expected);
    }

    private void VerifyCveFlushes(string fixtureName, DeltaJobExpectedFixture expected)
    {
        _flushedCveBatches.Select(batch => batch.Count).Should().Equal(expected.ExpectedCveBatchSizes,
            "fixture {0}: {1}", fixtureName, expected.Description);

        if (expected.ExpectedCveIdsByBatch is not null)
        {
            for (var i = 0; i < expected.ExpectedCveIdsByBatch.Count; i++)
            {
                _flushedCveBatches[i].Select(item => item.CveId).Should().Equal(
                    expected.ExpectedCveIdsByBatch[i],
                    "fixture {0}, flush {1}: {2}", fixtureName, i, expected.Description);
            }
        }

        if (expected.ExpectedModifiedByCveId is not null)
        {
            foreach (var (cveId, modified) in expected.ExpectedModifiedByCveId)
            {
                _flushedCveBatches
                    .SelectMany(batch => batch)
                    .Single(item => item.CveId == cveId)
                    .Modified.Should().Be(modified,
                        "fixture {0}: {1}", fixtureName, expected.Description);
            }
        }
    }

    private void VerifyVendorFlushes(string fixtureName, DeltaJobExpectedFixture expected)
    {
        if (expected.ExpectedVendorBatches is null)
            return;

        _flushedVendorBatches.Should().HaveCount(expected.ExpectedVendorBatches.Count,
            "fixture {0}: {1}", fixtureName, expected.Description);

        for (var i = 0; i < expected.ExpectedVendorBatches.Count; i++)
        {
            var captured = _flushedVendorBatches[i];
            var expectedBatch = expected.ExpectedVendorBatches[i];

            captured.Should().HaveCount(expectedBatch.Count,
                "fixture {0}, vendor flush {1}: {2}", fixtureName, i, expected.Description);

            foreach (var expectedVendor in expectedBatch)
            {
                captured.Single(vp => vp.Vendor == expectedVendor.Vendor).Softwares
                    .OrderBy(software => software).Should().Equal(
                        expectedVendor.Softwares.OrderBy(software => software),
                        "fixture {0}, vendor {1}: {2}", fixtureName, expectedVendor.Vendor, expected.Description);
            }
        }
    }

    private void VerifyInvariantVerdict(string fixtureName, DeltaJobExpectedFixture expected)
    {
        // When nothing was flushed the observed batch at the flush contract is empty,
        // which the size invariant must name instead of passing silently.
        var observedBatches = _flushedCveBatches.Count > 0
            ? _flushedCveBatches
            : (IReadOnlyList<IList<CveMongoModel>>)new List<IList<CveMongoModel>> { new List<CveMongoModel>() };

        var stored = expected.StoredModifiedByCveId ?? new Dictionary<string, DateTime>();

        var violations = observedBatches
            .SelectMany(batch => DeltaJobInvariants.CheckCveBatch(batch, stored))
            .Concat(_flushedVendorBatches.SelectMany(vendorBatch => DeltaJobInvariants.CheckDeduplication(vendorBatch)))
            .Distinct()
            .ToList();

        violations.Should().Equal(expected.ExpectedInvariantViolations,
            "fixture {0}: {1}", fixtureName, expected.Description);
    }

    private VulnerabilitiesJsonHelper CreateHelper()
    {
        return new VulnerabilitiesJsonHelper(
            _cveMongoService, Substitute.For<ICweMongoService>(), Substitute.For<ICapecMongoService>(),
            _vendorMongoService, CreateCompletedStateService(), Substitute.For<IBackgroundJobClient>(),
            BuildUrlsOptions(), _httpClientFactory, NullLogger<VulnerabilitiesJsonHelper>.Instance);
    }

    private static IInitialImportStateService CreateCompletedStateService()
    {
        var stateService = Substitute.For<IInitialImportStateService>();

        stateService
            .IsStepCompletedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        return stateService;
    }

    private static IOptions<VulnerabilitiesUrls> BuildUrlsOptions()
    {
        return Options.Create(new VulnerabilitiesUrls
        {
            StartTracking = 2018,
            CweUrl = "https://unit.test/cwe/cwec_v4.10.xml.zip",
            CapecUrl = "https://unit.test/capec/capec_v3.9.xml",
            CveJsonNameUrlTemplate = "https://unit.test/feeds/nvdcve-2.0-{0}.json.zip",
            CveJsonModifiedApiUrl = "https://unit.test/rest/json/cves/2.0/?lastModStartDate={0}-{1}-{2}T{3}:00:00.000&lastModEndDate={4}-{5}-{6}T{7}:00:00.000",
            CveJsonPublishedApiUrl = "https://unit.test/rest/json/cves/2.0/?pubStartDate={0}-{1}-{2}T{3}:00:00.000&pubEndDate={4}-{5}-{6}T{7}:00:00.000"
        });
    }

    private sealed class StubHttpHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _prefixResponses = new();

        public void RespondPrefix(string prefix, byte[] content)
        {
            _prefixResponses[prefix] = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestUrl = request.RequestUri!.ToString();

            var prefix = _prefixResponses.Keys.FirstOrDefault(requestUrl.StartsWith);

            if (prefix == null)
                throw new HttpRequestException($"No preconfigured response for {requestUrl}");

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(_prefixResponses[prefix])
            });
        }
    }
}
