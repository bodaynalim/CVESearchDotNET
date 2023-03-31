using Cve.Application.Services;
using Cve.DomainModels.MongoModels.Cve;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public class CveMongoService : BaseMongoService<CveMongoModel>, ICveMongoService
    {
        public CveMongoService(IMongoDatabase db) : base(db, "Cves")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.CveId), new CreateIndexOptions { Unique = true }));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Published)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Modified)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.Products)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.VulnerableConfigurations)));
        }

        public async Task<IList<CveMongoModel>> GetCveList(string vendor, string product, int count, int page, bool descending)
        {
            var filter = FilterDefinition<CveMongoModel>.Empty;

            filter = Builders<CveMongoModel>.Filter.ElemMatch(v => v.Products, x => x.Vendor == vendor);

            filter &= Builders<CveMongoModel>.Filter.ElemMatch(v => v.Products, x => x.Softwares.Any(s => s.SoftwareName == product));

            SortDefinition<CveMongoModel> sort = null;

            if(descending)
                sort = Builders<CveMongoModel>.Sort.Descending(v => v.Published);
            else
                sort = Builders<CveMongoModel>.Sort.Ascending(v => v.Published);

            page = page <= 0 ? 1 : page;

            var result = Collection.Find(filter).Skip((page - 1) * count).Limit(count).Sort(sort);

            return await result.ToListAsync();
        }

        public override async Task<CveMongoModel> CreateOrUpdateExisting(CveMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                var result = await Collection.DeleteOneAsync(e => e.CveId == item.CveId);

                return result.IsAcknowledged && result.DeletedCount > 0 ? await CreateNewItem(item) : any;
            }
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
