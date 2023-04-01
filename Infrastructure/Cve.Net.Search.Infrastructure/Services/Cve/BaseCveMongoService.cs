using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Linq;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public abstract class BaseCveMongoService : BaseMongoService<CveMongoModel>
    {
        public BaseCveMongoService(IMongoDatabase db, string collectionName) : base(db, collectionName)
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Published)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Modified)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.Products)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.VulnerableConfigurations)));
        }

        public override async Task<CveMongoModel> CreateNewItemIfNotExist(CveMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any != null)
                return any;

            await Collection.InsertOneAsync(item);

            return item;
        }

        public override async Task<CveMongoModel> Get(string id)
        {
            return await Collection.Find(s => s.CveId == id).FirstOrDefaultAsync();
        }
    }
}
