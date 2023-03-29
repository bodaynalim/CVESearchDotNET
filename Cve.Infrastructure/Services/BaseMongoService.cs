using Cve.Application.Services;
using Cve.DomainModels.MongoModels;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public abstract class BaseMongoService<T> : IBaseMongoService<T>
        where T: BaseMongoModel
    {
        /// <summary>
        /// Constructor of the base service.
        /// </summary>
        /// <param name="db">Mongo database.</param>
        /// <param name="fileService">File storage service.</param>
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
        public virtual async Task<T> CreateNewItem(T item)
        {
            await Collection.InsertOneAsync(item);

            return item;
        }

        /// <inheritdoc />
        public abstract Task<T> CreateOrUpdateExisting(T item);

        /// <inheritdoc />
        public virtual async Task<bool> ContainsAnyItems()
        {
            return await Collection.CountDocumentsAsync(FilterDefinition<T>.Empty) > 0;
        }

        /// <inheritdoc />
        public abstract Task<T> CreateNewItemIfNotExist(T item);
    }
}
