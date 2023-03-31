using Cve.Application.Services;
using Cve.DomainModels.MongoModels.Capec;
using MongoDB.Driver;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public class CapecMongoService : BaseMongoService<CapecMongoModel>, ICapecMongoService
    {
        public CapecMongoService(IMongoDatabase db) : base(db, "Capecs")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Ascending(c => c.CapecId), new CreateIndexOptions { Unique = true }));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCapecs)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)));
        }

        public override async Task<CapecMongoModel> CreateOrUpdateExisting(CapecMongoModel item)
        {
            var any = await Collection.Find(s => s.CapecId == item.CapecId).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                var result = await Collection.DeleteOneAsync(e => e.CapecId == item.CapecId);

                return result.IsAcknowledged && result.DeletedCount > 0 ? await CreateNewItem(item) : any;
            }
        }

        public override async Task<CapecMongoModel> CreateNewItemIfNotExist(CapecMongoModel item)
        {
            var any = await Collection.Find(s => s.CapecId == item.CapecId).FirstOrDefaultAsync();

            if (any != null)
                return any;

            await Collection.InsertOneAsync(item);

            return item;
        }

        public override async Task<CapecMongoModel> Get(string id)
        {
            return await Collection.Find(s => s.CapecId == id).FirstOrDefaultAsync();
        }
    }
}
