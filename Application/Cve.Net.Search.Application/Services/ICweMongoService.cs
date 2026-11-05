using Cve.Net.Search.Domain.Database.MongoModels.Cwe;

namespace Cve.Application.Services;

public interface ICweMongoService : IBaseMongoService<CweMongoModel>, IIndexInitializer
{
    /// <summary>
    /// Insert or (re)place given CWE items in a single bulk operation (upsert by CweId).
    /// </summary>
    /// <param name="items">CWEs to upsert</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateOrUpdateExisting(IList<CweMongoModel> items, CancellationToken cancellationToken = default);

    /// <summary>
    /// Number of CWE entries matching the keyword (null = all).
    /// </summary>
    Task<long> CountCwes(string? keyword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Page of CWE entries in fixed ascending-numeric-ID order. A null
    /// keyword lists all entries; otherwise entries whose ID or name
    /// contains the keyword (case-insensitive) are matched.
    /// </summary>
    /// <param name="keyword">Search phrase or null</param>
    /// <param name="count">Count</param>
    /// <param name="page">Page</param>
    /// <param name="cancellationToken"></param>
    /// <returns>The page entries and the total match count.</returns>
    Task<(IList<CweMongoModel> Items, long Total)> GetCweList(string? keyword, int count, int page, CancellationToken cancellationToken = default);
}
