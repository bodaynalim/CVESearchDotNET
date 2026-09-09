using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Infrastructure.Extensions;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels.NVDApi.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
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
    private readonly ICveMongoService _cveMongoService;
    private readonly ICweMongoService _cweMongoService;
    private readonly ICapecMongoService _capecMongoService;
    private readonly IVendorMongoService _vendorMongoService;
    private readonly VulnerabilitiesUrls _vulnerabilitiesUrls;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<VulnerabilitiesJsonHelper> _logger;

    public VulnerabilitiesJsonHelper(ICveMongoService cveMongoService,
        ICweMongoService cweMongoService, ICapecMongoService capecMongoService,
        IVendorMongoService vendorMongoService, IOptions<VulnerabilitiesUrls> cveUrls,
        IHttpClientFactory httpClientFactory, ILogger<VulnerabilitiesJsonHelper> logger)
    {
        _cveMongoService = cveMongoService;
        _cweMongoService = cweMongoService;
        _capecMongoService = capecMongoService;
        _vendorMongoService = vendorMongoService;
        _vulnerabilitiesUrls = cveUrls.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }
   
    public async Task PopulateDatabaseInitially(CancellationToken cancellationToken = default)
    {
        if (await _cveMongoService.ContainsAnyItems(cancellationToken))
            return;

        // Download and deserialize CWEs and CAPECs
        await DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl, cancellationToken);
        await DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl, cancellationToken);

        var currentYear = DateTime.UtcNow.Year;

        var countOfYears = currentYear - _vulnerabilitiesUrls.StartTracking;

        if (countOfYears > 0)
        {
            // Download and deserialize CVEs
            for (int i = 0; i <= countOfYears; i++)
            {
                var neededYear = _vulnerabilitiesUrls.StartTracking + i;
                await LoadCertainUrlCvesZip(string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, neededYear),
                   (c, ct) => _cveMongoService.CreateNewItem(c, ct), cancellationToken);
            }
        }            
    }

    public async Task LoadCwesAndCapecs(CancellationToken cancellationToken = default)
    {
        if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
            return;

        // Download and deserialize CWEs and CAPECs
        await DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl, cancellationToken);
        await DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl, cancellationToken);
    }

    public async Task LoadCurrentYearCves(CancellationToken cancellationToken = default)
    {
        if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
            return;

        //TODO: fix with NVD API 2.0
    }

    public async Task LoadCurrentDayCves(CancellationToken cancellationToken = default)
    {
        if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
            return;

        await LoadCvesUsingApi(false, cancellationToken);
    }

    public async Task LoadNewAndModifiedPerHourCves(CancellationToken cancellationToken = default)
    {
        if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
            return;

        await LoadCvesUsingApi(true, cancellationToken);
    }

    #region Private Helpers

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
            finishModified.Year, finishModified.Month, finishModified.Day, finishModified.Hour),
            (c, ct) => _cveMongoService.CreateOrUpdateExisting(c, ct), cancellationToken);

        // Download published CVEs json via new NVD 2.0 API
        await LoadCertainUrlCvesJson(string.Format(_vulnerabilitiesUrls.CveJsonPublishedApiUrl,
            startModified.Year, startModified.Month, startModified.Day, startModified.Hour,
            finishModified.Year, finishModified.Month, finishModified.Day, finishModified.Hour),
            (c, ct) => _cveMongoService.CreateOrUpdateExisting(c, ct), cancellationToken);
    }

    private async Task DeserializeAndSaveCveJson(string pathToJson, Func<CveMongoModel, CancellationToken, Task<CveMongoModel>> createItem,
        Func<JObject, (CveMongoModel, VulnerableProducts[])> converToMongoModel, CancellationToken cancellationToken)
    {
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
                if (jsonReader.TokenType != JsonToken.StartObject) continue;

                var item = JObject.Load(jsonReader);

                var (cve, vendors) = converToMongoModel.Invoke(item);

                await createItem.Invoke(cve, cancellationToken);

                // Create vendor entry in Db
                foreach (var vendor in vendors)
                    await _vendorMongoService.CreateOrUpdateVendor(vendor, cancellationToken);
            }
        }
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
                        (item, ct) => _capecMongoService.CreateOrUpdateExisting(item.ToCapecMongoModel(), ct), cancellationToken);
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"Failed to load Capec: {e.Message}");
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
                    (item, ct) => _cweMongoService.CreateOrUpdateExisting(item.ToCweMongoModel(), ct), cancellationToken);
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"Failed to load CWE: {e.Message}");
        }
        finally
        {
            Directory.Delete(tempRandomDir, true);
            File.Delete(tempRandomFile);
        }
    }

    private async Task DeserializeAndSaveXml<T>(string pathToXml, string rootAttributeName, string nameSpace, Func<T, CancellationToken, Task> saveToMongo, CancellationToken cancellationToken)
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

            do
            {
                await reader.MoveToContentAsync();

                var deserializedItem = (T)serializer.Deserialize(reader);

                await saveToMongo.Invoke(deserializedItem, cancellationToken);

            } while (reader.ReadToFollowing(rootAttributeName));
        }
    }

    /// <summary>
    /// Download ZIP file with CVEs json inside, unarchive and add them into DB
    /// </summary>
    /// <param name="url">URL to ZIP file</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    private async Task LoadCertainUrlCvesZip(string url, Func<CveMongoModel, CancellationToken, Task<CveMongoModel>> saveToMongo, CancellationToken cancellationToken)
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
                   saveToMongo,
                   (item) => item.ToObject<CveItemNewApi>().ToCveMongoModel(), cancellationToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"Failed to load {url} {jsonFile}: {e.Message}");
        }
        finally
        {
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
    private async Task LoadCertainUrlCvesJson(string url, Func<CveMongoModel, CancellationToken, Task<CveMongoModel>> saveToMongo, CancellationToken cancellationToken)
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

            await DeserializeAndSaveCveJson(tempRandomFile, saveToMongo,
                    (item) => item.ToObject<CveItemNewApi>().ToCveMongoModel(), cancellationToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"Failed to load {url} {jsonFile}: {e.Message}");
        }
        finally
        {
            File.Delete(tempRandomFile);
        }
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
