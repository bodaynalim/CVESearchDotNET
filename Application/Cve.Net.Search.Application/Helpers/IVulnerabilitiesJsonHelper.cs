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
    /// Import the CVE year archive (part of the initial database population).
    /// Runs as a separate chained job per year, so one year failing or rerunning
    /// never affects the other years.
    /// </summary>
    /// <param name="year">Year archive to import, e.g. 2024</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Mutex("InitialImportCvesYear-{0}")]
    Task ImportCvesYear(int year, CancellationToken cancellationToken = default);

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
