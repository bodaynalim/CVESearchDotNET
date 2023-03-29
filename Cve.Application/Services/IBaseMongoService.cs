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
        Task<T> CreateNewItem(T item);

        /// <summary>
        /// Create or replace existing one item
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        Task<T> CreateOrUpdateExisting(T item);

        /// <summary>
        /// Check if collection contains any item
        /// </summary>
        /// <returns></returns>
        Task<bool> ContainsAnyItems();

        /// <summary>
        /// Create new item if not exist
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        Task<T> CreateNewItemIfNotExist(T item);
    }
}
