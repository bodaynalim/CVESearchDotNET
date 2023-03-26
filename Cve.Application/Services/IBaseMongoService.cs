using Cve.DomainModels.MongoModels;

namespace Cve.Application.Services
{
    public interface IBaseMongoService<T>
        where T : BaseMongoModel
    {
        Task SaveItemToDatabase(T item);
    }
}
