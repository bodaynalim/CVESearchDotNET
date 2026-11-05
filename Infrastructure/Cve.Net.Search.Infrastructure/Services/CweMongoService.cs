using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cwe;
using MongoDB.Driver;
using System.Threading;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services;

public class CweMongoService : BaseMongoService<CweMongoModel>, ICweMongoService, IIndexInitializer
{
    public CweMongoService(IMongoDatabase db) : base(db, "Cwes")
    {
    }

    public async Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CweMongoModel>(Builders<CweMongoModel>.IndexKeys.Ascending(c => c.CweId), new CreateIndexOptions { Unique = true }), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CweMongoModel>(Builders<CweMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)), cancellationToken: cancellationToken);
    }

    public async Task CreateOrUpdateExisting(IList<CweMongoModel> items, CancellationToken cancellationToken = default)
    {
        if (items.Count == 0)
            return;

        // A replacement document carrying a null `_id` would alter the immutable
        // field on every update (bulk write error code 66). Pin each replacement
        // to its existing document's `_id` first.
        var cweIds = items.DistinctBy(s => s.CweId).Select(s => s.CweId).ToList();
        var existingIds = await Collection
            .Find(Builders<CweMongoModel>.Filter.In(c => c.CweId, cweIds))
            .Project(s => new { s.CweId, s.Id })
            .ToListAsync(cancellationToken);
        var idByCweId = existingIds.ToDictionary(x => x.CweId, x => x.Id);

        var bulkModels = items
            .DistinctBy(s => s.CweId)
            .Select(s =>
            {
                if (idByCweId.TryGetValue(s.CweId, out var id))
                    s.Id = id;

                return new ReplaceOneModel<CweMongoModel>(
                    Builders<CweMongoModel>.Filter.Eq(c => c.CweId, s.CweId),
                    s)
                {
                    IsUpsert = true
                };
            });

        await Collection.BulkWriteAsync(bulkModels, new BulkWriteOptions { IsOrdered = false }, cancellationToken);
    }

    public override async Task<CweMongoModel> CreateOrUpdateExisting(CweMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.CweId == item.CweId).FirstOrDefaultAsync(cancellationToken);

        if (any == null)
            return await CreateNewItem(item, cancellationToken);
        else
        {
            item.Id = any.Id;

            var result = await Collection.ReplaceOneAsync(e => e.CweId == item.CweId, item, cancellationToken: cancellationToken);

            return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
        }
    }

    public override async Task<CweMongoModel> CreateNewItemIfNotExist(CweMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.CweId == item.CweId).FirstOrDefaultAsync(cancellationToken);

        if (any != null)
            return any;

        await Collection.InsertOneAsync(item, cancellationToken: cancellationToken);

        return item;
    }

    public override async Task<CweMongoModel> Get(string id, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(s => s.CweId == id).FirstOrDefaultAsync(cancellationToken);
    }
}
