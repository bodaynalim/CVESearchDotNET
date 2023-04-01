using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cwe;
using MongoDB.Driver;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public class CweMongoService : BaseMongoService<CweMongoModel>, ICweMongoService
    {
        public CweMongoService(IMongoDatabase db) : base(db, "Cwes")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CweMongoModel>(Builders<CweMongoModel>.IndexKeys.Ascending(c => c.CweId), new CreateIndexOptions { Unique = true}));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CweMongoModel>(Builders<CweMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)));
        }

        public override async Task<CweMongoModel> CreateOrUpdateExisting(CweMongoModel item)
        {
            var any = await Collection.Find(s => s.CweId == item.CweId).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                var result = await Collection.DeleteOneAsync(e => e.CweId == item.CweId);

                return result.IsAcknowledged && result.DeletedCount > 0 ? await CreateNewItem(item) : any;
            }
        }

        public override async Task<CweMongoModel> CreateNewItemIfNotExist(CweMongoModel item)
        {
            var any = await Collection.Find(s => s.CweId == item.CweId).FirstOrDefaultAsync();

            if (any != null)
                return any;

            await Collection.InsertOneAsync(item);

            return item;
        }

        public override async Task<CweMongoModel> Get(string id)
        {
            return await Collection.Find(s => s.CweId == id).FirstOrDefaultAsync();
        }
    }
}
