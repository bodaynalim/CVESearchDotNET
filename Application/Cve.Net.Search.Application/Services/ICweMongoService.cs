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
}
