using Cve.DomainModels.MongoModels;

namespace Cve.Application.Services
{
    public interface IBaseMongoService<T>
        where T : BaseMongoModel
    {
        /// <summary>
        /// Create new item in database
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        Task<T> SaveItemToDatabase(T item);

        /// <summary>
        /// Check if collection contains any item
        /// </summary>
        /// <returns></returns>
        Task<bool> ContainsAnyItems();
    }
}
