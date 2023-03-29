using Cve.DomainModels.MongoModels;

namespace Cve.Application.Services
{
    public interface ICveMongoService : IBaseMongoService<CveMongoModel>
    {
        Task<IList<CveMongoModel>> GetCveList(string vendor, string product, int count, int page, bool descending);
    }
}
