using System.Text;
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
/// Delta-job tests over the same seam as VulnerabilitiesJsonHelperInitialImportTests
/// (T12): the NVD delta feed is stubbed at the HTTP seam, the Mongo services are
/// NSubstitutes, and the flushed batches are captured and checked against the T12
/// data-quality invariants. No Mongo connection is made (AGENTS.md §2).
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

        // The published window returns an empty delta by default; each test stubs the
        // modified window explicitly.
        RespondPublished(DeltaJobDataQualityFixtures.EmptyDeltaPayload);
    }

    #region Fixture: valid delta input → expected output, all invariants hold

    [Fact]
    public async Task LoadCurrentDayCves_WithValidDeltaFixture_FlushesExpectedOutputSatisfyingAllInvariants()
    {
        RespondModified(DeltaJobDataQualityFixtures.BuildValidDeltaPayload());

        await CreateHelper().LoadCurrentDayCves();

        _flushedCveBatches.Should().HaveCount(1);
        var batch = _flushedCveBatches.Single();

        // Input → output: both feed entries reach Mongo, in feed order.
        batch.Select(item => item.CveId).Should()
            .Equal(DeltaJobDataQualityFixtures.FirstCveId, DeltaJobDataQualityFixtures.SecondCveId);

        batch.Select(item => item.Modified).Should().Equal(
            DeltaJobDataQualityFixtures.ParseTimestamp(DeltaJobDataQualityFixtures.FirstCveModified),
            DeltaJobDataQualityFixtures.ParseTimestamp(DeltaJobDataQualityFixtures.SecondCveModified));

        // Ids non-empty and unique within the batch, dedup sound, size sane.
        DeltaJobInvariants.CheckCveBatch(batch, new Dictionary<string, DateTime>()).Should().BeEmpty();

        // Vendor aggregation dedup: one entry per vendor, softwares collapsed.
        _flushedVendorBatches.Should().HaveCount(1);
        var vendorProducts = _flushedVendorBatches.Single();

        vendorProducts.Count.Should().Be(2);
        vendorProducts.Single(vp => vp.Vendor == "acme").Softwares
            .OrderBy(s => s).Should().Equal("gadget", "widget");
        vendorProducts.Single(vp => vp.Vendor == "beta").Softwares
            .Should().Equal("gadget");

        DeltaJobInvariants.CheckDeduplication(vendorProducts).Should().BeEmpty();
    }

    #endregion

    #region Negative: a deliberately violating feed fails with the invariant's name

    [Fact]
    public async Task LoadCurrentDayCves_WithDuplicateCveIdInFeed_FailsWithIdsAndDedupInvariantNames()
    {
        RespondModified(DeltaJobDataQualityFixtures.BuildDuplicateIdDeltaPayload());

        await CreateHelper().LoadCurrentDayCves();

        // The helper hands both occurrences downstream (the keep-first dedup runs inside
        // the Mongo service); the flushed batch therefore carries the duplicates, and
        // the invariant check names exactly what is violated instead of passing silently.
        _flushedCveBatches.Should().HaveCount(1);
        var batch = _flushedCveBatches.Single();
        batch.Should().HaveCount(2);

        var violations = DeltaJobInvariants.CheckCveBatch(batch);

        violations.Should().Contain(DeltaJobInvariants.IdsNonEmptyAndUniqueWithinBatch);
        violations.Should().Contain(DeltaJobInvariants.DeduplicationAsDesigned);
    }

    [Fact]
    public async Task LoadCurrentDayCves_WithEmptyDelta_FlushesNothingAndFailsSizeInvariant()
    {
        RespondModified(DeltaJobDataQualityFixtures.EmptyDeltaPayload);

        await CreateHelper().LoadCurrentDayCves();

        _flushedCveBatches.Should().BeEmpty();
        _flushedVendorBatches.Should().BeEmpty();

        // An empty delta is never a silent ok: the size invariant flags it as a failure.
        DeltaJobInvariants.CheckDeltaSize(new List<CveMongoModel>())
            .Should().Contain(DeltaJobInvariants.DeltaSizeSane);
    }

    [Fact]
    public async Task LoadCurrentDayCves_WithOlderModifiedInLaterRun_FailsWithMonotonicInvariantName()
    {
        // Run 1 stores the CVE with the newer modification date.
        RespondModified(DeltaJobDataQualityFixtures.BuildSingleCveDeltaPayload(
            DeltaJobDataQualityFixtures.FirstCveId, "2026-02-02T00:00:00Z"));

        await CreateHelper().LoadCurrentDayCves();

        var stored = _flushedCveBatches.Single().ToDictionary(item => item.CveId, item => item.Modified);

        // Run 2 re-delivers the same CVE with an older modification date.
        RespondModified(DeltaJobDataQualityFixtures.BuildSingleCveDeltaPayload(
            DeltaJobDataQualityFixtures.FirstCveId, "2026-02-01T00:00:00Z"));

        await CreateHelper().LoadCurrentDayCves();

        var secondRunBatch = _flushedCveBatches.Last();

        DeltaJobInvariants.CheckCveBatch(secondRunBatch, stored)
            .Should().Contain(DeltaJobInvariants.ModificationDatesMonotonic);
    }

    #endregion

    #region Positive: unchanged modification dates never violate monotonicity

    [Fact]
    public async Task LoadCurrentDayCves_WithUnchangedModifiedInLaterRun_ReportsNoViolations()
    {
        RespondModified(DeltaJobDataQualityFixtures.BuildSingleCveDeltaPayload(
            DeltaJobDataQualityFixtures.FirstCveId, "2026-02-02T00:00:00Z"));

        await CreateHelper().LoadCurrentDayCves();

        var stored = _flushedCveBatches.Single().ToDictionary(item => item.CveId, item => item.Modified);

        RespondModified(DeltaJobDataQualityFixtures.BuildSingleCveDeltaPayload(
            DeltaJobDataQualityFixtures.FirstCveId, "2026-02-02T00:00:00Z"));

        await CreateHelper().LoadCurrentDayCves();

        DeltaJobInvariants.CheckCveBatch(_flushedCveBatches.Last(), stored).Should().BeEmpty();
    }

    #endregion

    #region Positive: batching keeps every flush bounded with unique ids across the run

    [Fact]
    public async Task LoadCurrentDayCves_WithMoreCvesThanBatchSize_FlushesBoundedBatchesWithUniqueIds()
    {
        RespondModified(DeltaJobDataQualityFixtures.BuildSizedDeltaPayload(
            DeltaJobInvariants.MaxCveBatchSize + 1));

        await CreateHelper().LoadCurrentDayCves();

        _flushedCveBatches.Should().HaveCount(2, "the helper flushes at the 1000-item boundary");
        _flushedCveBatches[0].Should().HaveCount(DeltaJobInvariants.MaxCveBatchSize);
        _flushedCveBatches[1].Should().HaveCount(1);

        _flushedCveBatches
            .SelectMany(batch => batch)
            .Select(item => item.CveId)
            .Distinct()
            .Should().HaveCount(DeltaJobInvariants.MaxCveBatchSize + 1,
                "every id across the whole delta run is unique");

        foreach (var batch in _flushedCveBatches)
            DeltaJobInvariants.CheckCveBatch(batch).Should().BeEmpty();
    }

    #endregion

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

    private void RespondModified(string payload)
    {
        _httpHandler.RespondPrefix(ModifiedApiPrefix, Encoding.UTF8.GetBytes(payload));
    }

    private void RespondPublished(string payload)
    {
        _httpHandler.RespondPrefix(PublishedApiPrefix, Encoding.UTF8.GetBytes(payload));
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
