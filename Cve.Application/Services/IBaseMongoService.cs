using Cve.DomainModels.MongoModels;

namespace Cve.Application.Services
{
    public interface IBaseMongoService<T>
        where T : BaseMongoModel
    {
        Task<T> SaveItemToDatabase(T item);

        Task<bool> ContainsAnyItems();
    }
}
