using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.DomainModels.Configuration;
using Cve.DomainModels.CveXmlJsonModels;
using Cve.DomainModels.MongoModels.Cve;
using Cve.Infrastructure.Extensions;
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
                    await LoadCertainUrlCves(string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, neededYear),
                       (c) => _cveMongoService.CreateNewItem(c));
                }
            }            
        }

        public async Task LoadNewAndModifiedCves()
        {
            if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
                return;

            // Download and deserialize CWEs and CAPECs
            await DeserializeAndSaveCweXml(_vulnerabilitiesUrls.CweUrl);
            await DeserializeAndSaveCapecXml(_vulnerabilitiesUrls.CapecUrl);

            // Download and deserialize current year CVEs
            var currentYear = DateTime.UtcNow.Year;
            await LoadCertainUrlCves(string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, currentYear),
                (c) => _cveMongoService.CreateNewItemIfNotExist(c));

            // Download and deserialize recent CVEs
            await LoadCertainUrlCves(_vulnerabilitiesUrls.CveRecentUrl, 
                (c) => _cveMongoService.CreateNewItemIfNotExist(c));

            // Download and deserialize modified CVEs
            await LoadCertainUrlCves(_vulnerabilitiesUrls.CveModifiedUrl,
                (c) => _cveMongoService.CreateNewItemIfNotExist(c));
        }

        #region Private Helpers

        private async Task DeserializeAndSaveCveJson(string pathToJson, Func<CveMongoModel, Task<CveMongoModel>> createItem)
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

                    var (cve, vendors) = item.ToObject<CveItemModel>().ToCveMongoModel();

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

        private async Task LoadCertainUrlCves(string url, Func<CveMongoModel, Task<CveMongoModel>> saveToMongo)
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

                    await DeserializeAndSaveCveJson(jsonFile,
                        saveToMongo);
                }
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

        #endregion
    }
}
