using System.IO.Compression;
using System.Net;
using System.Text;
using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Helpers;
using Cve.Infrastructure.Services;
using Cve.Infrastructure.Services.InitialImport;
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
/// Tests for the daily current-year catch-up job: it must download the
/// current-year archive feed and persist via upserts (delta semantics),
/// unlike the initial year import which only inserts new items.
/// </summary>
public class VulnerabilitiesJsonHelperCurrentYearTests
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

    public VulnerabilitiesJsonHelperCurrentYearTests()
    {
        // Every baseline marker is complete, so the job is allowed to run.
        _initialImportStateService
            .IsStepCompletedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        _httpClientFactory.CreateClient().Returns(_ => new HttpClient(_httpHandler));

        _httpHandler.Respond("https://unit.test/feeds/nvdcve-2.0-" + CurrentYear + ".json.zip",
            BuildCurrentYearCveZipContent());
    }

    [Fact]
    public async Task LoadCurrentYearCves_WhenBaselineReady_DownloadsCurrentYearZipAndUpserts()
    {
        var helper = CreateHelper();

        await helper.LoadCurrentYearCves();

        _httpHandler.Requests.Should().Contain(url => url.Contains("nvdcve-2.0-" + CurrentYear));

        await _cveMongoService.Received(1).CreateOrUpdateExisting(
            Arg.Is<IList<CveMongoModel>>(items => items.Select(i => i.CveId).OrderBy(id => id)
                .SequenceEqual(new[] { $"CVE-{CurrentYear}-0001", $"CVE-{CurrentYear}-0002" })),
            Arg.Any<CancellationToken>());

        _cveMongoService.ReceivedCalls().Where(c => c.GetMethodInfo().Name == nameof(ICveMongoService.CreateNewItems))
            .Should().BeEmpty("catch-up semantics are upsert, not insert-only");

        await _vendorMongoService.Received(1).BulkUpsertVendors(
            Arg.Is<IList<(string Vendor, IReadOnlyList<string> Softwares)>>(vendors =>
                vendors.Count == 2
                && vendors.Any(v => v.Vendor == "acme"
                                    && v.Softwares.OrderBy(s => s).SequenceEqual(new[] { "gadget", "widget" }))
                && vendors.Any(v => v.Vendor == "beta"
                                    && v.Softwares.OrderBy(s => s).SequenceEqual(new[] { "gadget" }))),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoadCurrentYearCves_WhenBaselineIncomplete_NoOps()
    {
        // Default substitute returns false for every marker: baseline not ready.
        var incompleteState = Substitute.For<IInitialImportStateService>();
        var helper = CreateHelper(incompleteState);

        await helper.LoadCurrentYearCves();

        _httpHandler.Requests.Should().BeEmpty();
        _cveMongoService.ReceivedCalls().Should().BeEmpty();
        _vendorMongoService.ReceivedCalls().Should().BeEmpty();
    }

    private VulnerabilitiesJsonHelper CreateHelper(IInitialImportStateService? stateService = null)
    {
        return new VulnerabilitiesJsonHelper(
            _cveMongoService, _cweMongoService, _capecMongoService, _vendorMongoService,
            stateService ?? _initialImportStateService, _backgroundJobClient, BuildUrlsOptions(),
            _httpClientFactory, NullLogger<VulnerabilitiesJsonHelper>.Instance);
    }

    private static IOptions<VulnerabilitiesUrls> BuildUrlsOptions()
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

        public List<string> Requests { get; } = new();

        public void Respond(string url, byte[] content) => Responses[url] = content;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // RequestUri is guaranteed non-null for requests produced by HttpClient itself.
            var requestUrl = request.RequestUri!.ToString();

            lock (Requests)
            {
                Requests.Add(requestUrl);
            }

            if (!Responses.TryGetValue(requestUrl, out var content))
            {
                throw new HttpRequestException($"No preconfigured response for {requestUrl}");
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) });
        }
    }
}
