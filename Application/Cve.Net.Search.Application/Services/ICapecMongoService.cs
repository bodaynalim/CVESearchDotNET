using Cve.Net.Search.Domain.Database.MongoModels.Capec;

namespace Cve.Application.Services;

public interface ICapecMongoService : IBaseMongoService<CapecMongoModel>, IIndexInitializer
{
    /// <summary>
    /// Insert or (re)place given CAPEC items in a single bulk operation (upsert by CapecId).
    /// </summary>
    /// <param name="items">CAPECs to upsert</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateOrUpdateExisting(IList<CapecMongoModel> items, CancellationToken cancellationToken = default);
}
