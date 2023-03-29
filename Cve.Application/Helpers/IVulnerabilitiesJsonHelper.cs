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
    }
}
