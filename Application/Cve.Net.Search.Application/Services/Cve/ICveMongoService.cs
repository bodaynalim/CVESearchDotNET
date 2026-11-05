using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Net.Search.Application.Services.Cve;

public interface ICveMongoService : IBaseMongoService<CveMongoModel>, IIndexInitializer
{
    /// <summary>
    /// Get CVEs list for specific vendor and product
    /// </summary>
    /// <param name="vendor">Vendor</param>
    /// <param name="product">Product</param>
    /// <param name="count">Count</param>
    /// <param name="page">Page</param>
    /// <param name="descending">True if order by descending</param>
    /// <param name="byPublished">True if order by published date (else by modified date)</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IList<CveMongoModel>> GetCveList(string vendor, string product, int count,
        int page, bool descending, bool byPublished = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Insert given CVE items in a single batch operation.
    /// Items already present (same CveId) are skipped.
    /// </summary>
    /// <param name="items">CVEs to insert</param>
    /// <param name="cancellationToken"></param>
    /// <returns>The list of items that were actually inserted.</returns>
    Task<IList<CveMongoModel>> CreateNewItems(IList<CveMongoModel> items, CancellationToken cancellationToken = default);

    /// <summary>
    /// Insert or (re)place given CVE items in a single bulk operation (upsert by CveId).
    /// </summary>
    /// <param name="items">CVEs to upsert</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateOrUpdateExisting(IList<CveMongoModel> items, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the CveIds from the given candidate ids that are already stored in the collection.
    /// </summary>
    /// <param name="cveIds">Candidate CveIds</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IList<string>> GetExistingCveIds(IEnumerable<string> cveIds, CancellationToken cancellationToken = default);

    Task<long> CountCves(string vendor, string product, CancellationToken cancellationToken = default);

    Task<CveMongoModel> GetLastOnePublished(string vendor, string product, CancellationToken cancellationToken = default);

    Task<CveMongoModel> GetLastOneModified(string vendor, string product, CancellationToken cancellationToken = default);
}
