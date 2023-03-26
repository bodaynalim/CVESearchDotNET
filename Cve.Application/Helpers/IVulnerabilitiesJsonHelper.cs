using Cve.DomainModels.MongoModels;

namespace Cve.Application.Helpers
{
    public interface IVulnerabilitiesJsonHelper
    {
        /// <summary>
        /// Deserialize CVEs json and save into Mongo DB
        /// </summary>
        /// <param name="pathToCve">Path to JSON</param>
        Task DeserializeAndSaveCveJson(string pathToCve);

        /// <summary>
        /// Deserialize CWEs xml and save into Mongo DB
        /// </summary>
        /// <param name="pathToXml">Path to Xml</param>
        Task DeserializeAndSaveCweXml(string pathToXml);

        /// <summary>
        /// Deserialize CAPECs xml and save into Mongo DB
        /// </summary>
        /// <param name="pathToXml"></param>
        /// <returns></returns>
        Task DeserializeAndSaveCapecXml(string pathToXml);
    }
}
