using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.DomainModels.CveXmlJsonModels;
using Cve.Infrastructure.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
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

        public VulnerabilitiesJsonHelper(ICveMongoService cveMongoService, 
            ICweMongoService cweMongoService, ICapecMongoService capecMongoService)
        {
            _cveMongoService = cveMongoService;
            _cweMongoService = cweMongoService;
            _capecMongoService = capecMongoService;
        }

        public async Task PopulateDatabaseInitially()
        {
            if (await _cveMongoService.ContainsAnyItems())
                return;

            await DeserializeAndSaveCveJson(@"Data\nvdcve-1.1-2020.json");
            await DeserializeAndSaveCveJson(@"Data\nvdcve-1.1-2021.json");
            await DeserializeAndSaveCveJson(@"Data\nvdcve-1.1-2022.json");
            await DeserializeAndSaveCveJson(@"Data\nvdcve-1.1-2023.json");
            await DeserializeAndSaveCweXml(@"Data\cwec_v4.4.xml");
            await DeserializeAndSaveCapecXml(@"Data\capec_v3.7.xml");
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

                    await _cveMongoService.SaveItemToDatabase(item.ToObject<CveItemModel>().ToCveMongoModel());
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
