using Cve.Net.Search.Infrastructure.Attributes.Jobs;

namespace Cve.Application.Helpers
{
    /// <summary>
    /// Helper for update CVEs, CWEs, CAPECs in db
    /// </summary>
    public interface IVulnerabilitiesJsonHelper
    {
        /// <summary>
        /// Populate initially database with items
        /// </summary>
        /// <returns></returns>
        [Mutex("PopulateDatabaseInitially")]
        Task PopulateDatabaseInitially();

        /// <summary>
        /// Load published and modified per hour CVEs items
        /// </summary>
        /// <returns></returns>
        [Mutex("LoadNewAndModifiedCves")]
        Task LoadNewAndModifiedPerHourCves();

        /// <summary>
        /// Load current year CVEs
        /// </summary>
        /// <returns></returns>
        [Mutex("LoadNewAndModifiedCves")]
        Task LoadCurrentYearCves();

        /// <summary>
        /// Load CWEs and CAPECs
        /// </summary>
        /// <returns></returns>
        [Mutex("LoadCwesAndCapecs")]
        Task LoadCwesAndCapecs();

        /// <summary>
        /// Load modified and published per day CVEs
        /// </summary>
        /// <returns></returns>
        [Mutex("LoadNewAndModifiedCves")]
        Task LoadCurrentDayCves();
    }
}
