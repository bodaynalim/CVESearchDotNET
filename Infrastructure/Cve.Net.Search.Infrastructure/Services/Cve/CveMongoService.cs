using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Cve.Net.Search.Infrastructure.Services.Cve;

public class CveMongoService : BaseMongoService<CveMongoModel>, ICveMongoService
{
    public CveMongoService(IMongoDatabase db) : base(db, "Cves")
    {
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>
            .IndexKeys
            .Ascending(c => c.CveId), new CreateIndexOptions { Unique = true }));
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Published)));
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Modified)));
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.Products)));
        Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.VulnerableConfigurations)));
    }

    public override async Task<CveMongoModel> CreateOrUpdateExisting(CveMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync(cancellationToken);

        if (any == null)
            return await CreateNewItem(item, cancellationToken);
        else
        {
            item.Id = any.Id;

            var result = await Collection.ReplaceOneAsync(e => e.CveId == item.CveId, item, cancellationToken: cancellationToken);

            return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
        }
    }

    public async Task<IList<CveMongoModel>> GetCveList(string vendor, string product, int count,
        int page, bool descending, bool byPublished, CancellationToken cancellationToken = default)
    {
        var filter = GetVendorProductFilter(vendor, product);

        SortDefinition<CveMongoModel> sort = (byPublished, descending) switch
        {
            (true, true) => Builders<CveMongoModel>.Sort.Descending(v => v.Published),
            (true, false) => Builders<CveMongoModel>.Sort.Ascending(v => v.Published),
            (false, true) => Builders<CveMongoModel>.Sort.Descending(v => v.Modified),
            (false, false) => Builders<CveMongoModel>.Sort.Ascending(v => v.Modified),
        };

        page = page <= 0 ? 1 : page;

        var result = Collection.Find(filter).Skip((page - 1) * count).Limit(count).Sort(sort);

        return await result.ToListAsync(cancellationToken);
    }

    public override async Task<CveMongoModel> CreateNewItemIfNotExist(CveMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync(cancellationToken);

        if (any != null)
            return any;

        await Collection.InsertOneAsync(item, cancellationToken: cancellationToken);

        return item;
    }

    public override async Task<CveMongoModel> Get(string id, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(s => s.CveId == id).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<CveMongoModel> GetLastOnePublished(string vendor, string product, CancellationToken cancellationToken = default)
    {
        var filter = GetVendorProductFilter(vendor, product);

        var sort = Builders<CveMongoModel>.Sort.Descending(v => v.Published);

        return await Collection.Find(filter).Sort(sort).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<CveMongoModel> GetLastOneModified(string vendor, string product, CancellationToken cancellationToken = default)
    {
        var filter = GetVendorProductFilter(vendor, product);

        var sort = Builders<CveMongoModel>.Sort.Descending(v => v.Modified);

        return await Collection.Find(filter).Sort(sort).FirstOrDefaultAsync(cancellationToken);
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
