using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Threading.Tasks;

namespace Cve.Net.Search.Infrastructure.Services.Cve
{
    public class CveModifiedMongoService : BaseCveMongoService, ICveModifiedMongoService
    {
        public CveModifiedMongoService(IMongoDatabase db) : base(db, "CvesModified")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>
                .IndexKeys
                .Ascending(c => c.CveId)));           
        }

        public override async Task<CveMongoModel> CreateOrUpdateExisting(CveMongoModel item)
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
    }
}
