using System.IO.Compression;
using System.Net;
using System.Text;
using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Infrastructure.Helpers;
using Cve.Net.Search.Infrastructure.Configuration;
using FluentAssertions;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace Cve.Net.Search.Tests;

public class VulnerabilitiesJsonHelperInitialImportTests
{
    private const int StartTrackingYear = 2018;

    private static readonly int CurrentYear = DateTime.UtcNow.Year;

    private readonly ICveMongoService _cveMongoService = Substitute.For<ICveMongoService>();
    private readonly ICweMongoService _cweMongoService = Substitute.For<ICweMongoService>();
    private readonly ICapecMongoService _capecMongoService = Substitute.For<ICapecMongoService>();
    private readonly IVendorMongoService _vendorMongoService = Substitute.For<IVendorMongoService>();
    private readonly IInitialImportStateService _initialImportStateService = Substitute.For<IInitialImportStateService>();
    private readonly IBackgroundJobClient _backgroundJobClient = Substitute.For<IBackgroundJobClient>();
    private readonly IHttpClientFactory _httpClientFactory = Substitute.For<IHttpClientFactory>();
    private readonly StubHttpHandler _httpHandler = new();

    public VulnerabilitiesJsonHelperInitialImportTests()
    {
        // Every initial-import step is marked completed except the CVEs of the current year.
        _initialImportStateService
            .IsStepCompletedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        _initialImportStateService
            .IsStepCompletedAsync("cves-" + CurrentYear, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(false));

        _cveMongoService
            .GetExistingCveIds(Arg.Any<IEnumerable<string>>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IList<string>>(new List<string>()));

        _httpClientFactory.CreateClient().Returns(_ => new HttpClient(_httpHandler));

        _httpHandler.Respond("https://unit.test/feeds/nvdcve-2.0-" + CurrentYear + ".json.zip",
            BuildCurrentYearCveZipContent());
    }

    #region Orchestrator: enqueues one job per pending year, chained sequentially

    [Fact]
    public async Task PopulateDatabaseInitially_WhenAllStepsCompleted_DoesNotEnqueueAnything()
    {
        var helper = CreateHelper(CompletedStateService());

        await helper.PopulateDatabaseInitially();

        _httpHandler.Requests.Should().BeEmpty();
        _backgroundJobClient.ReceivedCalls().Should().BeEmpty();
        _cveMongoService.ReceivedCalls().Should().BeEmpty();
    }

    [Fact]
    public async Task PopulateDatabaseInitially_WhenOnlyCurrentYearIncomplete_EnqueuesExactlyThatYear()
    {
        var helper = CreateHelper(_initialImportStateService);

        await helper.PopulateDatabaseInitially();

        _httpHandler.Requests.Should().BeEmpty("the orchestrator must not download, the year jobs do");

        var createdJobs = GetCreatedJobs(_backgroundJobClient);

        createdJobs.Should().HaveCount(1);
        AssertImportCvesYearJob(createdJobs[0].Job, CurrentYear);
        createdJobs[0].State.Should().BeOfType<EnqueuedState>("the first pending year starts the chain");
    }

    [Fact]
    public async Task PopulateDatabaseInitially_WhenNoYearCompleted_ChainsAllYearsSequentially()
    {
        // CWE/CAPEC baseline already there, every CVE year still pending.
        var yearStepsPending = Substitute.For<IInitialImportStateService>();
        yearStepsPending
            .IsStepCompletedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));
        yearStepsPending
            .IsStepCompletedAsync(Arg.Is<string>(step => step.StartsWith("cves-", StringComparison.Ordinal)),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(false));

        var helper = CreateHelper(yearStepsPending);

        await helper.PopulateDatabaseInitially();

        var expectedYears = Enumerable.Range(StartTrackingYear, CurrentYear - StartTrackingYear + 1).ToList();

        var createdJobs = GetCreatedJobs(_backgroundJobClient);

        createdJobs.Should().HaveCount(expectedYears.Count);

        foreach (var (index, expectedYear) in expectedYears.Select((year, index) => (index, year)))
        {
            AssertImportCvesYearJob(createdJobs[index].Job, expectedYear);

            if (index == 0)
            {
                createdJobs[index].State.Should().BeOfType<EnqueuedState>("the first pending year starts the chain");
            }
            else
            {
                // Continuations are represented as AwaitingState; OnAnyFinishedState makes the
                // chain failure-tolerant: a permanently failed year does not block later years.
                var awaitingState = createdJobs[index].State.Should().BeOfType<AwaitingState>().Which;

                awaitingState.Options.Should().Be(JobContinuationOptions.OnAnyFinishedState);
            }
        }
    }

    #endregion

    #region Regression: initial import used to be aborted by the 30-minute Hangfire fetch timeout;
    // retried runs were impossible, leaving a permanently partial database.

    [Fact]
    public async Task ImportCvesYear_WhenStepIncomplete_DownloadsImportsAndMarksStep()
    {
        var helper = CreateHelper(_initialImportStateService);

        await helper.ImportCvesYear(CurrentYear);

        _httpHandler.Requests.Should().Contain(url => url.Contains("nvdcve-2.0-" + CurrentYear));

        await _cveMongoService.Received(1).CreateNewItems(
            Arg.Is<IList<CveMongoModel>>(items => items.Select(i => i.CveId).OrderBy(id => id)
                .SequenceEqual(new[] { $"CVE-{CurrentYear}-0001", $"CVE-{CurrentYear}-0002" })),
            Arg.Any<CancellationToken>());

        await _initialImportStateService.Received(1).MarkStepCompletedAsync(
            "cves-" + CurrentYear, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ImportCvesYear_WhenStepAlreadyCompleted_DoesNothing()
    {
        var helper = CreateHelper(CompletedStateService());

        await helper.ImportCvesYear(CurrentYear);

        _httpHandler.Requests.Should().BeEmpty();
        _cveMongoService.ReceivedCalls().Should().BeEmpty();
    }

    [Fact]
    public async Task ImportCvesYear_WhenDownloadFails_PropagatesExceptionAndDoesNotMarkStep()
    {
        // A factory whose handler has no configured responses: every download fails.
        var failingHandler = new StubHttpHandler();
        var failingFactory = Substitute.For<IHttpClientFactory>();
        failingFactory.CreateClient().Returns(new HttpClient(failingHandler));

        var helper = CreateHelper(_initialImportStateService, failingFactory);

        await Assert.ThrowsAnyAsync<Exception>(() => helper.ImportCvesYear(CurrentYear));

        await _initialImportStateService.DidNotReceive()
            .MarkStepCompletedAsync("cves-" + CurrentYear, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ImportCvesYear_CollapsesVendorProductsIntoSingleBulkUpsert()
    {
        var helper = CreateHelper(_initialImportStateService);

        await helper.ImportCvesYear(CurrentYear);

        // CVE "…-0001" belongs to vendor "acme" (product "widget");
        // CVE "…-0002" belongs to "acme" ("gadget") and "beta" ("gadget").
        // Expected: exactly one bulk upsert with distinct vendors and merged product sets.
        await _vendorMongoService.Received(1).BulkUpsertVendors(
            Arg.Is<IList<(string Vendor, IReadOnlyList<string> Softwares)>>(vendors =>
                vendors.Count == 2
                && vendors.Any(v => v.Vendor == "acme"
                                    && v.Softwares.OrderBy(s => s).SequenceEqual(new[] { "gadget", "widget" }))
                && vendors.Any(v => v.Vendor == "beta"
                                    && v.Softwares.OrderBy(s => s).SequenceEqual(new[] { "gadget" }))),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Delta jobs are gated by persistent baseline markers (MemoryStorage loses job history on restart)

    [Fact]
    public async Task LoadNewAndModifiedPerHourCves_WhenCveBaselineIncomplete_Skips()
    {
        var helper = CreateHelper(_initialImportStateService);

        await helper.LoadNewAndModifiedPerHourCves();

        _httpHandler.Requests.Should().BeEmpty();
        _cveMongoService.ReceivedCalls().Should().BeEmpty();
    }

    [Fact]
    public async Task LoadNewAndModifiedPerHourCves_WhenCveBaselineComplete_Imports()
    {
        // The NVD API URLs contain dynamic date windows: respond to any URL under the API prefix.
        _httpHandler.RespondPrefix("https://unit.test/rest/json/cves/2.0/",
            Encoding.UTF8.GetBytes(BuildEmptyJson()));

        var helper = CreateHelper(CompletedStateService());

        await helper.LoadNewAndModifiedPerHourCves();

        _httpHandler.Requests
            .Where(url => url.StartsWith("https://unit.test/rest/json/cves/2.0/", StringComparison.Ordinal))
            .Should().HaveCount(2, "modified and published API windows must both be fetched");
    }

    [Fact]
    public async Task LoadCwesAndCapecs_WhenCweCapecBaselineIncomplete_Skips()
    {
        // CWE marker missing (default substitute returns false for everything).
        var incompleteState = Substitute.For<IInitialImportStateService>();
        var helper = CreateHelper(incompleteState);

        await helper.LoadCwesAndCapecs();

        _httpHandler.Requests.Should().BeEmpty();
    }

    #endregion

    private VulnerabilitiesJsonHelper CreateHelper(IInitialImportStateService stateService, IHttpClientFactory httpClientFactory = null)
    {
        return new VulnerabilitiesJsonHelper(
            _cveMongoService, _cweMongoService, _capecMongoService, _vendorMongoService,
            stateService, _backgroundJobClient, BuildUrlsOptions(),
            httpClientFactory ?? _httpClientFactory, NullLogger<VulnerabilitiesJsonHelper>.Instance);
    }

    /// <summary>
    /// Hangfire's Enqueue/ContinueJobWith are extension methods that funnel into
    /// IBackgroundJobClient.Create(Job, IState): the created Job already contains the
    /// evaluated job method and arguments, which is what Hangfire will execute.
    /// </summary>
    private static List<(Job Job, IState State)> GetCreatedJobs(IBackgroundJobClient client)
    {
        return client.ReceivedCalls()
            .Where(call => call.GetMethodInfo().Name == "Create")
            .Select(call => ((Job)call.GetArguments()[0], (IState)call.GetArguments()[1]))
            .ToList();
    }

    private static void AssertImportCvesYearJob(Job job, int expectedYear)
    {
        job.Method.Name.Should().Be(nameof(IVulnerabilitiesJsonHelper.ImportCvesYear));
        job.Args.Should().HaveCount(2);
        job.Args[0].Should().Be(expectedYear);
    }

    private static IInitialImportStateService CompletedStateService()
    {
        var substitute = Substitute.For<IInitialImportStateService>();
        substitute
            .IsStepCompletedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));
        return substitute;
    }

    private IOptions<VulnerabilitiesUrls> BuildUrlsOptions()
    {
        return Microsoft.Extensions.Options.Options.Create(new VulnerabilitiesUrls
        {
            StartTracking = StartTrackingYear,
            CweUrl = "https://unit.test/cwe/cwec_v4.10.xml.zip",
            CapecUrl = "https://unit.test/capec/capec_v3.9.xml",
            CveJsonNameUrlTemplate = "https://unit.test/feeds/nvdcve-2.0-{0}.json.zip",
            CveJsonModifiedApiUrl = "https://unit.test/rest/json/cves/2.0/?lastModStartDate={0}-{1}-{2}T{3}:00:00.000&lastModEndDate={4}-{5}-{6}T{7}:00:00.000",
            CveJsonPublishedApiUrl = "https://unit.test/rest/json/cves/2.0/?pubStartDate={0}-{1}-{2}T{3}:00:00.000&pubEndDate={4}-{5}-{6}T{7}:00:00.000"
        });
    }

    private static string BuildEmptyJson() => "[]";

    private static byte[] BuildCurrentYearCveZipContent()
    {
        const string json = """
        [
          {
            "cve": {
              "id": "CVE-2026-0001",
              "sourceIdentifier": "test@unit.test",
              "published": "2026-01-01T00:00:00Z",
              "lastModified": "2026-02-01T00:00:00Z",
              "descriptions": [ { "lang": "en", "value": "First" } ],
              "references": [],
              "metrics": {},
              "weaknesses": [],
              "configurations": [
                {
                  "nodes": [
                    {
                      "operator": "OR",
                      "negate": false,
                      "cpeMatch": [
                        { "vulnerable": true, "matchCriteriaId": "2b28319b-5c16-42e2-9a01-000000000001", "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*" }
                      ]
                    }
                  ]
                }
              ]
            }
          },
          {
            "cve": {
              "id": "CVE-2026-0002",
              "sourceIdentifier": "test@unit.test",
              "published": "2026-01-02T00:00:00Z",
              "lastModified": "2026-02-02T00:00:00Z",
              "descriptions": [ { "lang": "en", "value": "Second" } ],
              "references": [],
              "metrics": {},
              "weaknesses": [],
              "configurations": [
                {
                  "nodes": [
                    {
                      "operator": "OR",
                      "negate": false,
                      "cpeMatch": [
                        { "vulnerable": true, "matchCriteriaId": "2b28319b-5c16-42e2-9a01-000000000002", "criteria": "cpe:2.3:a:acme:gadget:2.0:*:*:*:*:*:*:*" },
                        { "vulnerable": true, "matchCriteriaId": "2b28319b-5c16-42e2-9a01-000000000003", "criteria": "cpe:2.3:a:beta:gadget:2.0:*:*:*:*:*:*:*" }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
        """;

        var jsonWithCurrentYear = json
            .Replace("CVE-2026-0001", $"CVE-{CurrentYear}-0001", StringComparison.Ordinal)
            .Replace("CVE-2026-0002", $"CVE-{CurrentYear}-0002", StringComparison.Ordinal);

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry($"nvdcve-2.0-{CurrentYear}.json");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write(jsonWithCurrentYear);
        }

        return ms.ToArray();
    }

    private sealed class StubHttpHandler : HttpMessageHandler
    {
        public Dictionary<string, byte[]> Responses { get; } = new();

        public Dictionary<string, byte[]> PrefixResponses { get; } = new();

        public List<string> Requests { get; } = new();

        public void Respond(string url, byte[] content) => Responses[url] = content;

        public void RespondPrefix(string prefix, byte[] content) => PrefixResponses[prefix] = content;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestUrl = request.RequestUri!.ToString();

            lock (Requests)
            {
                Requests.Add(requestUrl);
            }

            if (!Responses.TryGetValue(requestUrl, out var content) &&
                !PrefixResponses.TryGetValue(
                    PrefixResponses.Keys.FirstOrDefault(requestUrl.StartsWith) ?? string.Empty, out content))
            {
                throw new HttpRequestException($"No preconfigured response for {requestUrl}");
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) });
        }
    }
}
