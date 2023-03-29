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
        Task PopulateDatabaseInitially();

        /// <summary>
        /// Load new CVEs items
        /// </summary>
        /// <returns></returns>
        Task LoadNewAndModifiedCves();
    }
}
