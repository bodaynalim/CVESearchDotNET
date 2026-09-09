using Cve.Net.Search.Domain.Database.MongoModels;

namespace Cve.Application.Services;

public interface IBaseMongoService<T>
    where T : BaseMongoModel
{
    /// <summary>
    /// Get item by ID
    /// </summary>
    /// <param name="id"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<T> Get(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Create new item in database
    /// </summary>
    /// <param name="item"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<T> CreateNewItem(T item, CancellationToken cancellationToken = default);

    /// <summary>
    /// Create or replace existing one item
    /// </summary>
    /// <param name="item"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<T> CreateOrUpdateExisting(T item, CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if collection contains any item
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<bool> ContainsAnyItems(CancellationToken cancellationToken = default);

    /// <summary>
    /// Create new item if not exist
    /// </summary>
    /// <param name="item"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<T> CreateNewItemIfNotExist(T item, CancellationToken cancellationToken = default);
}
