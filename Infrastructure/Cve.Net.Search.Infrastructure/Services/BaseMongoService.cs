using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels;
using MongoDB.Driver;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services;

public abstract class BaseMongoService<T> : IBaseMongoService<T>
    where T: BaseMongoModel
{
    /// <summary>
    /// Constructor of the base service.
    /// </summary>
    /// <param name="db">Mongo database.</param>
    /// <param name="collectionName">Collection name.</param>
    protected BaseMongoService(IMongoDatabase db, string collectionName)
    {
        Db = db;
        Collection = db.GetCollection<T>(collectionName);
    }

    /// <summary>
    /// Reference to the Mongo database.
    /// </summary>
    protected IMongoDatabase Db { get; }

    /// <summary>
    /// Reference to the base items collection.
    /// </summary>
    protected IMongoCollection<T> Collection { get; }

    /// <inheritdoc />
    public virtual async Task<T> CreateNewItem(T item, CancellationToken cancellationToken = default)
    {
        await Collection.InsertOneAsync(item, cancellationToken: cancellationToken);

        return item;
    }

    /// <inheritdoc />
    public abstract Task<T> CreateOrUpdateExisting(T item, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public virtual async Task<bool> ContainsAnyItems(CancellationToken cancellationToken = default)
    {
        return await Collection.CountDocumentsAsync(FilterDefinition<T>.Empty, cancellationToken: cancellationToken) > 0;
    }

    /// <inheritdoc />
    public abstract Task<T> CreateNewItemIfNotExist(T item, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract Task<T> Get(string id, CancellationToken cancellationToken = default);
}
