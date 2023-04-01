using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Net.Search.Application.Services.Cve
{
    public interface ICveModifiedMongoService : IBaseMongoService<CveMongoModel>
    {
    }
}
