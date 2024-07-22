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
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace Cve.Infrastructure.Helpers
{
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
       
        public async Task PopulateDatabaseInitially()
        {
            if (await _cveMongoService.ContainsAnyItems())
                return;

            // Download and deserialize CWEs and CAPECs
            await DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl);
            await DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl);

            var currentYear = DateTime.UtcNow.Year;

            var countOfYears = currentYear - _vulnerabilitiesUrls.StartTracking;

            if (countOfYears > 0)
            {
                // Download and deserialize CVEs
                for (int i = 0; i <= countOfYears; i++)
                {
                    var neededYear = _vulnerabilitiesUrls.StartTracking + i;
                    await LoadCertainUrlCvesZip(string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, neededYear),
                       (c) => _cveMongoService.CreateNewItem(c));
                }
            }            
        }

        public async Task LoadCwesAndCapecs()
        {
            if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
                return;

            // Download and deserialize CWEs and CAPECs
            await DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl);
            await DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl);
        }

        public async Task LoadCurrentYearCves()
        {
            if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
                return;

            //TODO: fix with NVD API 2.0
            // Download and deserialize current year CVEs
            //var currentYear = DateTime.UtcNow.Year;
            ////await LoadCertainUrlCvesZip(string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, currentYear),
            ////    (c) => _cveMongoService.CreateOrUpdateExisting(c));
        }

        public async Task LoadCurrentDayCves()
        {
            if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
                return;

            await LoadCvesUsingApi(false);
        }

        public async Task LoadNewAndModifiedPerHourCves()
        {
            if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
                return;

            //TODO: fix with NVD 2.0 API or delete at all
            //// Download and deserialize recent CVEs
            //await LoadCertainUrlCvesZip(_vulnerabilitiesUrls.CveRecentUrl,
            //    (c) => _cveMongoService.CreateOrUpdateExisting(c));

            //// Download and deserialize modified CVEs
            //await LoadCertainUrlCvesZip(_vulnerabilitiesUrls.CveModifiedUrl,
            //    (c) => _cveMongoService.CreateOrUpdateExisting(c));

            await LoadCvesUsingApi(true);
        }

        #region Private Helpers

        /// <summary>
        /// Retrieve CVE using NVD 2.0 API
        /// </summary>
        /// <param name="hourly">If true the period for retrieving is 2 hours, false - one day</param>
        /// <returns></returns>
        private async Task LoadCvesUsingApi(bool hourly)
        {
            var currentDate = DateTime.UtcNow;

            var finishModified = GetSplittedDate(currentDate);

            var startModified = GetSplittedDate(hourly ? currentDate.AddHours(-5) : currentDate.AddDays(-1));

            // Download modified CVEs json via new NVD 2.0 API
            await LoadCertainUrlCvesJson(string.Format(_vulnerabilitiesUrls.CveJsonModifiedApiUrl,
                startModified.Year, startModified.Month, startModified.Day, startModified.Hour,
                finishModified.Year, finishModified.Month, finishModified.Day, finishModified.Hour),
                (c) => _cveMongoService.CreateOrUpdateExisting(c));

            // Download published CVEs json via new NVD 2.0 API
            await LoadCertainUrlCvesJson(string.Format(_vulnerabilitiesUrls.CveJsonPublishedApiUrl,
                startModified.Year, startModified.Month, startModified.Day, startModified.Hour,
                finishModified.Year, finishModified.Month, finishModified.Day, finishModified.Hour),
                (c) => _cveMongoService.CreateOrUpdateExisting(c));
        }

        private async Task DeserializeAndSaveCveJson(string pathToJson, Func<CveMongoModel, Task<CveMongoModel>> createItem,
            Func<JObject, (CveMongoModel, VulnarableProducts[])> converToMongoModel)
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

                    await createItem.Invoke(cve);

                    // Create vendor entry in Db
                    foreach (var vendor in vendors)
                        await _vendorMongoService.CreateOrUpdateVendor(vendor);
                }
            }
        }

        private async Task DeserializeAndSaveCapecXml(string url)
        {
            var tempPath = Path.GetTempPath();
            var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.xml");

            try
            {
                using (var client = _httpClientFactory.CreateClient())
                {
                    await Download(client, tempRandomFile, url);

                    await DeserializeAndSaveXml<AttackPatternType>(tempRandomFile, "Attack_Pattern", "http://capec.mitre.org/capec-3",
                            (item) => _capecMongoService.CreateOrUpdateExisting(item.ToCapecMongoModel()));
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

        private async Task DeserializeAndSaveCweXml(string cweUrl)
        {
            var tempPath = Path.GetTempPath();
            var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.zip");
            var tempRandomDir = Path.Combine(tempPath, Path.GetRandomFileName());

            try
            {
                using (var client = _httpClientFactory.CreateClient())
                {
                    var file = await DownloadAndExtract(client, tempRandomFile, tempRandomDir,
                        cweUrl);

                    await DeserializeAndSaveXml<WeaknessType>(file, "Weakness", "http://cwe.mitre.org/cwe-6",
                        (item) => _cweMongoService.CreateOrUpdateExisting(item.ToCweMongoModel()));
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

        private async Task DeserializeAndSaveXml<T>(string pathToXml, string rootAttributeName, string nameSpace, Func<T, Task> saveToMongo)
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

                    await saveToMongo.Invoke(deserializedItem);

                } while (reader.ReadToFollowing(rootAttributeName));
            }
        }

        /// <summary>
        /// Download ZIP file with CVEs json inside, unarchive and add them into DB
        /// </summary>
        /// <param name="url">URL to ZIP file</param>
        /// <returns></returns>
        private async Task LoadCertainUrlCvesZip(string url, Func<CveMongoModel, Task<CveMongoModel>> saveToMongo)
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
                        url);                   
                }

                await DeserializeAndSaveCveJson(jsonFile,
                       saveToMongo, (item) => item.ToObject<CveItemModel>().ToCveMongoModel());
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
        /// <returns></returns>
        private async Task LoadCertainUrlCvesJson(string url, Func<CveMongoModel, Task<CveMongoModel>> saveToMongo)
        {
            var tempPath = Path.GetTempPath();
            var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.json");
            string jsonFile = string.Empty;

            try
            {
                using (var client = _httpClientFactory.CreateClient())
                {
                    await Download(client, tempRandomFile, url);                    
                }

                await DeserializeAndSaveCveJson(tempRandomFile, saveToMongo,
                        (item) => item.ToObject<CveItemNewApi>().ToCveMongoModel());
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
            string tempRandomDir, string url)
        {
            await Download(client, tempRandomFile, url);

            ZipFile.ExtractToDirectory(tempRandomFile, tempRandomDir, true);

            return Directory.GetFiles(tempRandomDir).FirstOrDefault();
        }

        private static async Task Download(HttpClient client, string tempRandomFile,
           string url)
        {
            var recent = await client.GetAsync(url);
            using (var fs = new FileStream(tempRandomFile, FileMode.Create))
            {
                await recent.Content.CopyToAsync(fs);
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
}
