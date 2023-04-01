using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Infrastructure.Extensions;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cve.Net.Search.Infrastructure.Services.Cve
{
    public class CveMongoService : BaseCveMongoService, ICveMongoService
    {
        private readonly ICveModifiedMongoService _cveModifiedMongoService;

        public CveMongoService(IMongoDatabase db, ICveModifiedMongoService cveModifiedMongoService) : base(db, "Cves")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>
                .IndexKeys
                .Ascending(c => c.CveId), new CreateIndexOptions { Unique = true }));
            _cveModifiedMongoService = cveModifiedMongoService;
        }

        public override async Task<CveMongoModel> CreateOrUpdateExisting(CveMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                item.Id = any.Id;

                if (item.Modified > any.Modified)
                {
                    any.Id = null;
                    await _cveModifiedMongoService.CreateNewItem(any);
                }

                var result = await Collection.ReplaceOneAsync(e => e.CveId == item.CveId, item);

                return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
            }
        }

        public async Task<IList<CveMongoModel>> GetCveList(string vendor, string product, int count,
            int page, bool descending, bool byPublished)
        {
            var filter = GetVendorProductFilter(vendor, product);

            SortDefinition<CveMongoModel> sort = null;

            switch (byPublished)
            {
                case true:
                    if (descending)
                        sort = Builders<CveMongoModel>.Sort.Descending(v => v.Published);
                    else
                        sort = Builders<CveMongoModel>.Sort.Ascending(v => v.Published);
                    break;

                case false:
                    if (descending)
                        sort = Builders<CveMongoModel>.Sort.Descending(v => v.Modified);
                    else
                        sort = Builders<CveMongoModel>.Sort.Ascending(v => v.Modified);
                    break;
            }


            page = page <= 0 ? 1 : page;

            var result = Collection.Find(filter).Skip((page - 1) * count).Limit(count).Sort(sort);

            return await result.ToListAsync();
        }

        public async Task<CveMongoModel> GetLastOnePublished(string vendor, string product)
        {
            var filter = GetVendorProductFilter(vendor, product);

            var sort = Builders<CveMongoModel>.Sort.Descending(v => v.Published);

            return await Collection.Find(filter).Sort(sort).FirstOrDefaultAsync();
        }

        public async Task<CveMongoModel> GetLastOneModified(string vendor, string product)
        {
            var filter = GetVendorProductFilter(vendor, product);

            var sort = Builders<CveMongoModel>.Sort.Descending(v => v.Modified);

            return await Collection.Find(filter).Sort(sort).FirstOrDefaultAsync();
        }

        #region Private

        private FilterDefinition<CveMongoModel> GetVendorProductFilter(string vendor, string product)
        {
            var filter = FilterDefinition<CveMongoModel>.Empty;

            filter = Builders<CveMongoModel>.Filter.ElemMatch(v => v.Products, x => x.Vendor == vendor);

            filter &= Builders<CveMongoModel>.Filter.ElemMatch(v => v.Products, x => x.Softwares.Any(s => s.SoftwareName == product));

            return filter;
        }

        #endregion
    }
}
