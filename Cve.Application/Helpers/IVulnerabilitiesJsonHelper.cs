using Cve.DomainModels.MongoModels;
using System.Threading.Tasks;

namespace Cve.Application.Helpers
{
    public interface IVulnerabilitiesJsonHelper
    {
        /// <summary>
        /// Populate initially database with items
        /// </summary>
        /// <returns></returns>
        Task PopulateDatabaseInitially();

        /// <summary>
        /// Load new CVEs items
        /// </summary>
        /// <returns></returns>
        Task LoadNewAndModifiedCves();

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
