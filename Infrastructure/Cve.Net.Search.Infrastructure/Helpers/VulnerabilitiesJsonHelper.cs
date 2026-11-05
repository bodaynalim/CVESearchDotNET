using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Extensions;
using Cve.Infrastructure.Services.InitialImport;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels.NVDApi.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Hangfire;
using Hangfire.States;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace Cve.Infrastructure.Helpers;

public class VulnerabilitiesJsonHelper : IVulnerabilitiesJsonHelper
{
    private const int CveBatchSize = 1000;
    private const int XmlBatchSize = 200;

    private readonly ICveMongoService _cveMongoService;
    private readonly ICweMongoService _cweMongoService;
    private readonly ICapecMongoService _capecMongoService;
    private readonly IVendorMongoService _vendorMongoService;
    private readonly IInitialImportStateService _initialImportStateService;
    private readonly IBackgroundJobClient _backgroundJobClient;
    private readonly VulnerabilitiesUrls _vulnerabilitiesUrls;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<VulnerabilitiesJsonHelper> _logger;

    public VulnerabilitiesJsonHelper(ICveMongoService cveMongoService,
        ICweMongoService cweMongoService, ICapecMongoService capecMongoService,
        IVendorMongoService vendorMongoService, IInitialImportStateService initialImportStateService,
        IBackgroundJobClient backgroundJobClient, IOptions<VulnerabilitiesUrls> cveUrls,
        IHttpClientFactory httpClientFactory, ILogger<VulnerabilitiesJsonHelper> logger)
    {
        _cveMongoService = cveMongoService;
        _cweMongoService = cweMongoService;
        _capecMongoService = capecMongoService;
        _vendorMongoService = vendorMongoService;
        _initialImportStateService = initialImportStateService;
        _backgroundJobClient = backgroundJobClient;
        _vulnerabilitiesUrls = cveUrls.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task PopulateDatabaseInitially(CancellationToken cancellationToken = default)
    {
        // Steps are idempotent and tracked via persistent markers (ImportState collection),
        // so an aborted or retried run resumes at the first not-completed step
        // instead of re-importing everything or stopping with partial data.

        // Download and deserialize CWEs and CAPECs
        await RunInitialStepAsync(InitialImportStateService.StepCwes,
            ct => DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl, ct), cancellationToken);

        await RunInitialStepAsync(InitialImportStateService.StepCapecs,
            ct => DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl, ct), cancellationToken);

        // Enqueue one job per pending CVE year and chain them sequentially, so years are
        // imported one at a time (deterministic NVD download / Mongo load) and every single
        // job fits into any fetch window. OnAnyFinishedState makes the chain failure-tolerant:
        // a permanently failed year (after Hangfire retries) does not block the later years;
        // its marker stays unset, so the next orchestrator run retries it.
        var pendingYears = new List<int>();

        foreach (var year in GetTrackedYears())
        {
            if (!await _initialImportStateService.IsStepCompletedAsync(
                    InitialImportStateService.StepCvesPrefix + year, cancellationToken))
                pendingYears.Add(year);
        }

        if (pendingYears.Count == 0)
        {
            _logger.LogInformation("Initial import: all CVE year steps are already completed");

            return;
        }

        var previousJobId = _backgroundJobClient.Enqueue<IVulnerabilitiesJsonHelper>(
            job => job.ImportCvesYear(pendingYears[0], CancellationToken.None));

        foreach (var year in pendingYears.Skip(1))
        {
            previousJobId = _backgroundJobClient.ContinueJobWith<IVulnerabilitiesJsonHelper>(previousJobId,
                job => job.ImportCvesYear(year, CancellationToken.None),
                new EnqueuedState(),
                JobContinuationOptions.OnAnyFinishedState);
        }

        _logger.LogInformation(
            "Initial import: enqueued {Count} CVE year jobs ({Years})", pendingYears.Count,
            string.Join(", ", pendingYears));
    }

    public async Task ImportCvesYear(int year, CancellationToken cancellationToken = default)
    {
        await RunInitialStepAsync($"{InitialImportStateService.StepCvesPrefix}{year}",
            ct => LoadCertainUrlCvesZip(string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, year), ct),
            cancellationToken);
    }

    private IEnumerable<int> GetTrackedYears()
    {
        var countOfYears = DateTime.UtcNow.Year - _vulnerabilitiesUrls.StartTracking;

        for (var i = 0; i <= countOfYears; i++)
            yield return _vulnerabilitiesUrls.StartTracking + i;
    }

    /// <summary>
    /// Returns true when the initial CWE/CAPEC baseline has been fully imported
    /// (used to gate the delta jobs until the database is ready).
    /// </summary>
    private async Task<bool> IsCweCapecBaselineReadyAsync(CancellationToken cancellationToken)
    {
        return await _initialImportStateService.IsStepCompletedAsync(InitialImportStateService.StepCwes, cancellationToken)
               && await _initialImportStateService.IsStepCompletedAsync(InitialImportStateService.StepCapecs, cancellationToken);
    }

    /// <summary>
    /// Returns true when every tracked CVE year has been initially imported
    /// (used to gate the delta jobs until the database is ready).
    /// </summary>
    private async Task<bool> IsCveBaselineReadyAsync(CancellationToken cancellationToken)
    {
        foreach (var year in GetTrackedYears())
        {
            if (!await _initialImportStateService.IsStepCompletedAsync(
                    InitialImportStateService.StepCvesPrefix + year, cancellationToken))
                return false;
        }

        return true;
    }

    public async Task LoadCwesAndCapecs(CancellationToken cancellationToken = default)
    {
        if (!await IsCweCapecBaselineReadyAsync(cancellationToken))
            return;

        // Download and deserialize CWEs and CAPECs
        await DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl, cancellationToken);
        await DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl, cancellationToken);
    }

    public async Task LoadCurrentYearCves(CancellationToken cancellationToken = default)
    {
        if (!await IsCveBaselineReadyAsync(cancellationToken))
            return;

        //TODO: fix with NVD API 2.0
    }

    public async Task LoadCurrentDayCves(CancellationToken cancellationToken = default)
    {
        if (!await IsCveBaselineReadyAsync(cancellationToken))
            return;

        await LoadCvesUsingApi(false, cancellationToken);
    }

    public async Task LoadNewAndModifiedPerHourCves(CancellationToken cancellationToken = default)
    {
        if (!await IsCveBaselineReadyAsync(cancellationToken))
            return;

        await LoadCvesUsingApi(true, cancellationToken);
    }

    #region Private Helpers

    /// <summary>
    /// Runs one initial-import step, skipping it when its completion marker already exists.
    /// The marker is written only when the whole step succeeds.
    /// </summary>
    private async Task RunInitialStepAsync(string step, Func<CancellationToken, Task> stepAction, CancellationToken cancellationToken)
    {
        if (await _initialImportStateService.IsStepCompletedAsync(step, cancellationToken))
        {
            _logger.LogInformation("Initial import step {Step} already completed, skipping", step);
            return;
        }

        await stepAction(cancellationToken);

        await _initialImportStateService.MarkStepCompletedAsync(step, cancellationToken);
    }

    /// <summary>
    /// Retrieve CVE using NVD 2.0 API
    /// </summary>
    /// <param name="hourly">If true the period for retrieving is 2 hours, false - one day</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    private async Task LoadCvesUsingApi(bool hourly, CancellationToken cancellationToken)
    {
        var currentDate = DateTime.UtcNow;

        var finishModified = GetSplittedDate(currentDate);

        var startModified = GetSplittedDate(hourly ? currentDate.AddHours(-5) : currentDate.AddDays(-1));

        // Download modified CVEs json via new NVD 2.0 API
        await LoadCertainUrlCvesJson(string.Format(_vulnerabilitiesUrls.CveJsonModifiedApiUrl,
            startModified.Year, startModified.Month, startModified.Day, startModified.Hour,
            finishModified.Year, finishModified.Month, finishModified.Day, finishModified.Hour), cancellationToken);

        // Download published CVEs json via new NVD 2.0 API
        await LoadCertainUrlCvesJson(string.Format(_vulnerabilitiesUrls.CveJsonPublishedApiUrl,
            startModified.Year, startModified.Month, startModified.Day, startModified.Hour,
            finishModified.Year, finishModified.Month, finishModified.Day, finishModified.Hour), cancellationToken);
    }

    /// <summary>
    /// Streams the JSON file and saves parsed items in batches:
    /// - CVEs: single bulk insert/upsert per batch (replaces one find+insert roundtrip per document)
    /// - Vendors: single bulk upsert per batch (replaces the N+1 find-then-update per product)
    /// </summary>
    private async Task DeserializeAndSaveCveJson(string pathToJson,
        Func<JObject, (CveMongoModel, VulnerableProducts[])> converToMongoModel,
        Func<IList<CveMongoModel>, IList<(string Vendor, IReadOnlyList<string> Softwares)>, CancellationToken, Task> flushBatch,
        CancellationToken cancellationToken)
    {
        var batch = new List<CveMongoModel>(CveBatchSize);
        var batchVendorProducts = new Dictionary<string, HashSet<string>>();

        using var stream = new FileStream(pathToJson, FileMode.Open, FileAccess.Read);
        using var reader = new StreamReader(stream);
        using var jsonReader = new JsonTextReader(reader)
        {
            SupportMultipleContent = true
        };

        while (jsonReader.Read())
        {
            if (jsonReader.TokenType != JsonToken.StartArray) continue;
            while (jsonReader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (jsonReader.TokenType != JsonToken.StartObject) continue;

                var item = JObject.Load(jsonReader);

                var (cve, vendors) = converToMongoModel.Invoke(item);

                batch.Add(cve);

                foreach (var vendor in vendors)
                {
                    if (!batchVendorProducts.TryGetValue(vendor.Vendor, out var softwares))
                    {
                        softwares = new HashSet<string>();
                        batchVendorProducts[vendor.Vendor] = softwares;
                    }

                    foreach (var software in vendor.Softwares.Select(s => s.SoftwareName))
                        softwares.Add(software);
                }

                if (batch.Count >= CveBatchSize)
                {
                    await flushBatch(batch, TakeVendorProducts(batchVendorProducts), cancellationToken);
                    batch = new List<CveMongoModel>(CveBatchSize);
                    batchVendorProducts = new Dictionary<string, HashSet<string>>();
                }
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (batch.Count > 0)
            await flushBatch(batch, TakeVendorProducts(batchVendorProducts), cancellationToken);
    }

    private static List<(string Vendor, IReadOnlyList<string> Softwares)> TakeVendorProducts(Dictionary<string, HashSet<string>> batchVendorProducts)
    {
        return batchVendorProducts
            .Select(kvp => (kvp.Key, (IReadOnlyList<string>)kvp.Value.ToList()))
            .ToList();
    }

    private async Task DeserializeAndSaveCapecXml(string url, CancellationToken cancellationToken)
    {
        var tempPath = Path.GetTempPath();
        var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.xml");

        try
        {
            using (var client = _httpClientFactory.CreateClient())
            {
                await Download(client, tempRandomFile, url, cancellationToken);

                await DeserializeAndSaveXml<AttackPatternType>(tempRandomFile, "Attack_Pattern", "http://capec.mitre.org/capec-3",
                    (items, ct) => _capecMongoService.CreateOrUpdateExisting(
                        items.Select(i => i.ToCapecMongoModel()).ToList(), ct), cancellationToken);
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to load Capec");

            // Do not swallow: the step marker stays unset and Hangfire retry will resume the import.
            throw;
        }
        finally
        {
            File.Delete(tempRandomFile);
        }
    }

    private async Task DeserializeAndSaveCweXml(string cweUrl, CancellationToken cancellationToken)
    {
        var tempPath = Path.GetTempPath();
        var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.zip");
        var tempRandomDir = Path.Combine(tempPath, Path.GetRandomFileName());

        try
        {
            using (var client = _httpClientFactory.CreateClient())
            {
                var file = await DownloadAndExtract(client, tempRandomFile, tempRandomDir,
                    cweUrl, cancellationToken);

                await DeserializeAndSaveXml<WeaknessType>(file, "Weakness", "http://cwe.mitre.org/cwe-6",
                    (items, ct) => _cweMongoService.CreateOrUpdateExisting(
                        items.Select(i => i.ToCweMongoModel()).ToList(), ct), cancellationToken);
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to load CWE");

            // Do not swallow: the step marker stays unset and Hangfire retry will resume the import.
            throw;
        }
        finally
        {
            if (Directory.Exists(tempRandomDir))
                Directory.Delete(tempRandomDir, true);

            File.Delete(tempRandomFile);
        }
    }

    /// <summary>
    /// Streams the XML file and saves parsed items in batches
    /// (single bulk upsert per batch instead of one roundtrip per document).
    /// </summary>
    private async Task DeserializeAndSaveXml<T>(string pathToXml, string rootAttributeName, string nameSpace,
        Func<IList<T>, CancellationToken, Task> flushBatch, CancellationToken cancellationToken)
    {
        using var reader = XmlReader.Create(pathToXml, new XmlReaderSettings
        {
            Async = true
        });
        {
            var serializer = new XmlSerializer(typeof(T), new XmlRootAttribute(rootAttributeName)
            {
                Namespace = nameSpace
            });

            reader.ReadToFollowing(rootAttributeName);

            var batch = new List<T>(XmlBatchSize);

            do
            {
                cancellationToken.ThrowIfCancellationRequested();

                await reader.MoveToContentAsync();

                var deserializedItem = (T)serializer.Deserialize(reader);

                batch.Add(deserializedItem);

                if (batch.Count >= XmlBatchSize)
                {
                    await flushBatch(batch, cancellationToken);
                    batch = new List<T>(XmlBatchSize);
                }

            } while (reader.ReadToFollowing(rootAttributeName));

            cancellationToken.ThrowIfCancellationRequested();

            if (batch.Count > 0)
                await flushBatch(batch, cancellationToken);
        }
    }

    /// <summary>
    /// Download ZIP file with CVEs json inside, unarchive and add them into DB
    /// </summary>
    /// <param name="url">URL to ZIP file</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    private async Task LoadCertainUrlCvesZip(string url, CancellationToken cancellationToken)
    {
        var tempPath = Path.GetTempPath();
        var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.zip");
        var tempRandomDir = Path.Combine(tempPath, Path.GetRandomFileName());
        string jsonFile = string.Empty;

        try
        {
            using (var client = _httpClientFactory.CreateClient())
            {
                jsonFile = await DownloadAndExtract(client, tempRandomFile, tempRandomDir,
                    url, cancellationToken);                   
            }

            await DeserializeAndSaveCveJson(jsonFile,
                (item) => item.ToObject<CveItemNewApi>().ToCveMongoModel(),
                (items, vendorProducts, ct) => FlushCveItemsCreateNew(items, vendorProducts, ct),
                cancellationToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to load {Url} {JsonFile}", url, jsonFile);

            // Do not swallow: the step marker stays unset and Hangfire retry will resume the import.
            throw;
        }
        finally
        {
            if (Directory.Exists(tempRandomDir))
                Directory.Delete(tempRandomDir, true);

            File.Delete(tempRandomFile);
        }
    }

    /// <summary>
    /// Download CVEs into json file and add them into DB
    /// </summary>
    /// <param name="url">URL to get json</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    private async Task LoadCertainUrlCvesJson(string url, CancellationToken cancellationToken)
    {
        var tempPath = Path.GetTempPath();
        var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.json");
        string jsonFile = string.Empty;

        try
        {
            using (var client = _httpClientFactory.CreateClient())
            {
                await Download(client, tempRandomFile, url, cancellationToken);                    
            }

            await DeserializeAndSaveCveJson(tempRandomFile,
                (item) => item.ToObject<CveItemNewApi>().ToCveMongoModel(),
                (items, vendorProducts, ct) => FlushCveItemsCreateOrUpdate(items, vendorProducts, ct),
                cancellationToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to load {Url} {JsonFile}", url, jsonFile);

            // Do not swallow: the step marker stays unset and Hangfire retry will resume the import.
            throw;
        }
        finally
        {
            File.Delete(tempRandomFile);
        }
    }

    /// <summary>
    /// Saves a parsed batch of CVEs (initial import: only new items are inserted)
    /// together with the aggregated vendor/product entry updates.
    /// </summary>
    private async Task FlushCveItemsCreateNew(IList<CveMongoModel> items,
        IList<(string Vendor, IReadOnlyList<string> Softwares)> vendorProducts, CancellationToken cancellationToken)
    {
        if (items.Count > 0)
            await _cveMongoService.CreateNewItems(items, cancellationToken);

        if (vendorProducts.Count > 0)
            await _vendorMongoService.BulkUpsertVendors(vendorProducts, cancellationToken);
    }

    /// <summary>
    /// Saves a parsed batch of CVEs as upserts (delta load: update existing + insert new)
    /// together with the aggregated vendor/product entry updates.
    /// </summary>
    private async Task FlushCveItemsCreateOrUpdate(IList<CveMongoModel> items,
        IList<(string Vendor, IReadOnlyList<string> Softwares)> vendorProducts, CancellationToken cancellationToken)
    {
        if (items.Count > 0)
            await _cveMongoService.CreateOrUpdateExisting(items, cancellationToken);

        if (vendorProducts.Count > 0)
            await _vendorMongoService.BulkUpsertVendors(vendorProducts, cancellationToken);
    }

    private static async Task<string> DownloadAndExtract(HttpClient client, string tempRandomFile,
        string tempRandomDir, string url, CancellationToken cancellationToken)
    {
        await Download(client, tempRandomFile, url, cancellationToken);

        ZipFile.ExtractToDirectory(tempRandomFile, tempRandomDir, true);

        return Directory.GetFiles(tempRandomDir).FirstOrDefault();
    }

    private static async Task Download(HttpClient client, string tempRandomFile,
       string url, CancellationToken cancellationToken)
    {
        var recent = await client.GetAsync(url, cancellationToken);

        // Fail fast on HTTP errors instead of deserializing an error page later.
        recent.EnsureSuccessStatusCode();

        using (var fs = new FileStream(tempRandomFile, FileMode.Create))
        {
            await recent.Content.CopyToAsync(fs, cancellationToken);
        }
    }

    private (string Year, string Month, string Day, string Hour) GetSplittedDate(DateTime date)
    {
        var year = date.Year.ToString();

        var day = date.Day < 10 ? $"0{date.Day}" : date.Day.ToString();

        var month = date.Month < 10 ? $"0{date.Month}" : date.Month.ToString();

        var hour = date.Hour < 10 ? $"0{date.Hour}" : date.Hour.ToString();

        return (year, month, day, hour);
    }

    #endregion
}
