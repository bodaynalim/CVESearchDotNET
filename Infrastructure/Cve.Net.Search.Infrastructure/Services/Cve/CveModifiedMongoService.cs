using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Threading.Tasks;

namespace Cve.Net.Search.Infrastructure.Services.Cve
{
    public class CveModifiedMongoService : BaseMongoService<CveModifiedMongoModel>, ICveModifiedMongoService
    {
        public CveModifiedMongoService(IMongoDatabase db) : base(db, "CvesModified")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveModifiedMongoModel>(Builders<CveModifiedMongoModel>
                .IndexKeys
                .Ascending(c => c.CveId)));

           Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveModifiedMongoModel>(Builders<CveModifiedMongoModel>
               .IndexKeys
               .Descending(c => c.Modified)));
        }

        public override async Task<CveModifiedMongoModel> CreateOrUpdateExisting(CveModifiedMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                item.Id = any.Id;

                var result = await Collection.ReplaceOneAsync(e => e.CveId == item.CveId, item);

                return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
            }
        }

        public override async Task<CveModifiedMongoModel> CreateNewItemIfNotExist(CveModifiedMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any != null)
                return any;

            await Collection.InsertOneAsync(item);

            return item;
        }

        public override async Task<CveModifiedMongoModel> Get(string id)
        {
            return await Collection.Find(s => s.CveId == id).FirstOrDefaultAsync();
        }

        public async Task LogChanges(CveMongoModel old, CveMongoModel newItem)
        {
            throw new System.NotImplementedException();
        }
    }
}
