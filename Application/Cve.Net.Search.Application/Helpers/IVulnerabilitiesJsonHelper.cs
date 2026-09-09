using Cve.Net.Search.Infrastructure.Attributes.Jobs;

namespace Cve.Application.Helpers;

/// <summary>
/// Helper for update CVEs, CWEs, CAPECs in db
/// </summary>
public interface IVulnerabilitiesJsonHelper
{
    /// <summary>
    /// Populate initially database with items
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Mutex("PopulateDatabaseInitially")]
    Task PopulateDatabaseInitially(CancellationToken cancellationToken = default);

    /// <summary>
    /// Load published and modified per hour CVEs items
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Mutex("LoadNewAndModifiedCves")]
    Task LoadNewAndModifiedPerHourCves(CancellationToken cancellationToken = default);

    /// <summary>
    /// Load current year CVEs
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Mutex("LoadNewAndModifiedCves")]
    Task LoadCurrentYearCves(CancellationToken cancellationToken = default);

    /// <summary>
    /// Load CWEs and CAPECs
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Mutex("LoadCwesAndCapecs")]
    Task LoadCwesAndCapecs(CancellationToken cancellationToken = default);

    /// <summary>
    /// Load modified and published per day CVEs
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Mutex("LoadNewAndModifiedCves")]
    Task LoadCurrentDayCves(CancellationToken cancellationToken = default);
}
