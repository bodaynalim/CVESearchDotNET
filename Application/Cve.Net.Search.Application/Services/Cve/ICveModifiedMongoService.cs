using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Net.Search.Application.Services.Cve;

public interface ICveModifiedMongoService : IBaseMongoService<CveModifiedMongoModel>
{
    /// <summary>
    /// Log changes
    /// </summary>
    /// <param name="old"></param>
    /// <param name="newItem"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task LogChanges(CveMongoModel old, CveMongoModel newItem, CancellationToken cancellationToken = default);
}
