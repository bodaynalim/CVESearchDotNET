using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.DomainModels.CveXmlJsonModels;
using Cve.Infrastructure.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.IO.Compression;
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

        public VulnerabilitiesJsonHelper(ICveMongoService cveMongoService,
            ICweMongoService cweMongoService, ICapecMongoService capecMongoService, IVendorMongoService vendorMongoService)
        {
            _cveMongoService = cveMongoService;
            _cweMongoService = cweMongoService;
            _capecMongoService = capecMongoService;
            _vendorMongoService = vendorMongoService;
        }

        public async Task PopulateDatabaseInitially()
        {
            if (await _cveMongoService.ContainsAnyItems())
                return;

            var tempPath = Path.GetTempPath();
            var firstJson = Path.Combine(tempPath, Path.GetRandomFileName());
            var secondJson = Path.Combine(tempPath, Path.GetRandomFileName());
            var thirdJson = Path.Combine(tempPath, Path.GetRandomFileName());
            var fourthJson = Path.Combine(tempPath, Path.GetRandomFileName());

            try
            { 
                ZipFile.ExtractToDirectory("Data\\nvdcve-1.1-2020.json.zip", firstJson, true);
                ZipFile.ExtractToDirectory("Data\\nvdcve-1.1-2021.json.zip", secondJson, true);
                ZipFile.ExtractToDirectory("Data\\nvdcve-1.1-2022.json.zip", thirdJson, true);
                ZipFile.ExtractToDirectory("Data\\nvdcve-1.1-2023.json.zip", fourthJson, true);

                await DeserializeAndSaveCveJson($"{firstJson}\\nvdcve-1.1-2020.json");
                await DeserializeAndSaveCveJson($"{secondJson}\\nvdcve-1.1-2021.json");
                await DeserializeAndSaveCveJson($"{thirdJson}\\nvdcve-1.1-2022.json");
                await DeserializeAndSaveCveJson($"{fourthJson}\\nvdcve-1.1-2023.json");
                await DeserializeAndSaveCweXml(@"Data\cwec_v4.4.xml");
                await DeserializeAndSaveCapecXml(@"Data\capec_v3.7.xml");
            }
            finally
            {
                File.Delete($"{firstJson}\\nvdcve-1.1-2020.json");
                File.Delete($"{secondJson}\\nvdcve-1.1-2021.json");
                File.Delete($"{thirdJson}\\nvdcve-1.1-2022.json");
                File.Delete($"{fourthJson}\\nvdcve-1.1-2023.json");
            }
        }

        public async Task LoadNewAndModifiedCves()
        {
            // TODO
        }

        public async Task DeserializeAndSaveCveJson(string pathToJson)
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

                    await _cveMongoService.SaveItemToDatabase(cve);

                    foreach (var vendor in vendors)
                        await _vendorMongoService.CreateOrUpdateVendor(vendor);
                }
            }
        }

        public async Task DeserializeAndSaveCweXml(string pathToXml)
        {
            await DeserializeAndSaveXml<WeaknessType>(pathToXml, "Weakness", "http://cwe.mitre.org/cwe-6",
                (item) => _cweMongoService.SaveItemToDatabase(item.ToCweMongoModel()));            
        }

        public async Task DeserializeAndSaveCapecXml(string pathToXml)
        {
            await DeserializeAndSaveXml<AttackPatternType>(pathToXml, "Attack_Pattern", "http://capec.mitre.org/capec-3",
                (item) => _capecMongoService.SaveItemToDatabase(item.ToCapecMongoModel()));
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
    } 
}
