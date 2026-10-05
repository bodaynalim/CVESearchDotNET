using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Capec;
using MongoDB.Driver;
using System.Threading;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services;

public class CapecMongoService : BaseMongoService<CapecMongoModel>, ICapecMongoService
{
    public CapecMongoService(IMongoDatabase db) : base(db, "Capecs")
    {
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Ascending(c => c.CapecId), new CreateIndexOptions { Unique = true }));
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCapecs)));
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)));
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
