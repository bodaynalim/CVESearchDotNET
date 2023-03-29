using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.DomainModels.Configuration;
using Cve.DomainModels.CveXmlJsonModels;
using Cve.DomainModels.MongoModels;
using Cve.Infrastructure.Extensions;
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

        public VulnerabilitiesJsonHelper(ICveMongoService cveMongoService,
            ICweMongoService cweMongoService, ICapecMongoService capecMongoService,
            IVendorMongoService vendorMongoService, IOptions<VulnerabilitiesUrls> cveUrls,
            IHttpClientFactory httpClientFactory)
        {
            _cveMongoService = cveMongoService;
            _cweMongoService = cweMongoService;
            _capecMongoService = capecMongoService;
            _vendorMongoService = vendorMongoService;
            _vulnerabilitiesUrls = cveUrls.Value;
            _httpClientFactory = httpClientFactory;
        }

        public async Task PopulateDatabaseInitially()
        {
            if (await _cveMongoService.ContainsAnyItems())
                return;

            var currentYear = DateTime.UtcNow.Year;

            var countOfYears = currentYear - _vulnerabilitiesUrls.StartTracking;

            if (countOfYears > 0)
            {
                for (int i = 0; i <= countOfYears; i++)
                {
                    var neededYear = _vulnerabilitiesUrls.StartTracking + i;
                    await LoadCertainYearCves(neededYear, (c) => _cveMongoService.CreateNewItem(c));
                }
            }

            await DeserializeAndSaveCweXml(@"Data\cwec_v4.4.xml");
            await DeserializeAndSaveCapecXml(@"Data\capec_v3.7.xml");
        }

        public async Task LoadNewAndModifiedCves()
        {
            if (BackgroundJobsModule.CheckJobIsRunningOrScheduledByName(nameof(PopulateDatabaseInitially)))
                return;

            var tempPath = Path.GetTempPath();
            var tempRandomRecentFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.zip");
            var tempRandomRecentDir = Path.Combine(tempPath, Path.GetRandomFileName());
            var tempRandomModifiedFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.zip");
            var tempRandomModifiedDir = Path.Combine(tempPath, Path.GetRandomFileName());

            try
            {
                var currentYear = DateTime.UtcNow.Year;
                await LoadCertainYearCves(currentYear, (c) => _cveMongoService.CreateNewItemIfNotExist(c));

                using (var client = _httpClientFactory.CreateClient())
                {
                    await DownloadAndExtract(client, tempRandomRecentFile, tempRandomRecentDir, _vulnerabilitiesUrls.CveRecentUrl);

                    await DeserializeAndSaveCveJson($"{tempRandomRecentDir}\\{_vulnerabilitiesUrls.CveRecentJsonName}",
                        (c) => _cveMongoService.CreateNewItemIfNotExist(c));

                    await DownloadAndExtract(client, tempRandomModifiedFile, tempRandomModifiedDir, _vulnerabilitiesUrls.CveModifiedUrl);

                    await DeserializeAndSaveCveJson($"{tempRandomModifiedDir}\\{_vulnerabilitiesUrls.CveModifiedJsonName}",
                        (c) => _cveMongoService.CreateOrUpdateExisting(c));
                }                
            }
            finally
            {
                Directory.Delete(tempRandomRecentDir, true);
                Directory.Delete(tempRandomModifiedDir, true);
                File.Delete(tempRandomRecentFile);
                File.Delete(tempRandomModifiedDir);
            }
        }        

        public async Task DeserializeAndSaveCveJson(string pathToJson, Func<CveMongoModel, Task<CveMongoModel>> createItem)
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

                    foreach (var vendor in vendors)
                        await _vendorMongoService.CreateOrUpdateVendor(vendor);
                }
            }
        }        

        public async Task DeserializeAndSaveCweXml(string pathToXml)
        {
            await DeserializeAndSaveXml<WeaknessType>(pathToXml, "Weakness", "http://cwe.mitre.org/cwe-6",
                (item) => _cweMongoService.CreateNewItem(item.ToCweMongoModel()));            
        }

        public async Task DeserializeAndSaveCapecXml(string pathToXml)
        {
            await DeserializeAndSaveXml<AttackPatternType>(pathToXml, "Attack_Pattern", "http://capec.mitre.org/capec-3",
                (item) => _capecMongoService.CreateNewItem(item.ToCapecMongoModel()));
        }

        #region Private Helpers

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

        private async Task LoadCertainYearCves(int year, Func<CveMongoModel, Task<CveMongoModel>> saveToMongo)
        {
            var tempPath = Path.GetTempPath();
            var tempRandomFile = Path.Combine(tempPath, $"{Path.GetRandomFileName()}.zip");
            var tempRandomDir = Path.Combine(tempPath, Path.GetRandomFileName());
            

            try
            {
                using (var client = _httpClientFactory.CreateClient())
                {
                    await DownloadAndExtract(client, tempRandomFile, tempRandomDir,
                        string.Format(_vulnerabilitiesUrls.CveJsonNameUrlTemplate, year));

                    await DeserializeAndSaveCveJson($"{tempRandomDir}\\{string.Format(_vulnerabilitiesUrls.CveJsonNameTemplate, year)}",
                        saveToMongo);
                }
            }
            catch(Exception e)
            {
                throw e;
            }
            finally
            {
                Directory.Delete(tempRandomDir, true);
                File.Delete(tempRandomFile);
            }
        }

        private static async Task DownloadAndExtract(HttpClient client, string tempRandomFile,
            string tempRandomDir, string url)
        {
            var recent = await client.GetAsync(url);
            using (var fs = new FileStream(tempRandomFile, FileMode.CreateNew))
            {
                await recent.Content.CopyToAsync(fs);
            }

            ZipFile.ExtractToDirectory(tempRandomFile, tempRandomDir, true);
        }

        #endregion
    }
}
