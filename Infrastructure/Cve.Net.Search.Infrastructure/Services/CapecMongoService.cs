using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Capec;
using MongoDB.Driver;
using System.Threading;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services;

public class CapecMongoService : BaseMongoService<CapecMongoModel>, ICapecMongoService, IIndexInitializer
{
    public CapecMongoService(IMongoDatabase db) : base(db, "Capecs")
    {
    }

    public async Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Ascending(c => c.CapecId), new CreateIndexOptions { Unique = true }), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCapecs)), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)), cancellationToken: cancellationToken);
    }

    public async Task CreateOrUpdateExisting(IList<CapecMongoModel> items, CancellationToken cancellationToken = default)
    {
        if (items.Count == 0)
            return;

        var bulkModels = items
            .DistinctBy(s => s.CapecId)
            .Select(s => new ReplaceOneModel<CapecMongoModel>(
                Builders<CapecMongoModel>.Filter.Eq(c => c.CapecId, s.CapecId),
                s)
            {
                IsUpsert = true
            });

        await Collection.BulkWriteAsync(bulkModels, new BulkWriteOptions { IsOrdered = false }, cancellationToken);
    }

    public override async Task<CapecMongoModel> CreateOrUpdateExisting(CapecMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.CapecId == item.CapecId).FirstOrDefaultAsync(cancellationToken);

        if (any == null)
            return await CreateNewItem(item, cancellationToken);
        else
        {
            item.Id = any.Id;

            var result = await Collection.ReplaceOneAsync(e => e.CapecId == item.CapecId, item, cancellationToken: cancellationToken);

            return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
        }
    }

    public override async Task<CapecMongoModel> CreateNewItemIfNotExist(CapecMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.CapecId == item.CapecId).FirstOrDefaultAsync(cancellationToken);

        if (any != null)
            return any;

        await Collection.InsertOneAsync(item, cancellationToken: cancellationToken);

        return item;
    }

    public override async Task<CapecMongoModel> Get(string id, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(s => s.CapecId == id).FirstOrDefaultAsync(cancellationToken);
    }
}
