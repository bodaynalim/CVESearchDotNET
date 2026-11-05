using Cve.Application.Services;
using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Cve.Net.Search.Infrastructure.Services.Cve;

public class CveMongoService : BaseMongoService<CveMongoModel>, ICveMongoService, IIndexInitializer
{
    public CveMongoService(IMongoDatabase db) : base(db, "Cves")
    {
    }

    public async Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>
            .IndexKeys
            .Ascending(c => c.CveId), new CreateIndexOptions { Unique = true }), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Published)), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Modified)), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.Products)), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.VulnerableConfigurations)), cancellationToken: cancellationToken);
    }

    public async Task<IList<CveMongoModel>> CreateNewItems(IList<CveMongoModel> items, CancellationToken cancellationToken = default)
    {
        // Deduplicate within the batch first (keep the first occurrence per CveId).
        items = items.DistinctBy(s => s.CveId).ToList();

        var cveIds = items.Select(s => s.CveId).ToList();
        var existingIds = await GetExistingCveIds(cveIds, cancellationToken);
        if (existingIds.Count > 0)
        {
            var existingIdSet = existingIds.ToHashSet();
            items = items.Where(s => !existingIdSet.Contains(s.CveId)).ToList();
        }

        if (items.Count == 0)
            return items;

        // IsOrdered:false keeps inserting after a failure, and a concurrent importer can
        // still win the race for the same CveId (unique index): duplicate-key write errors
        // are expected and treated as "already imported" instead of failing the batch.
        // Any non-duplicate-key error propagates (Hangfire retries; the retry pre-filters
        // by CveId, so it makes progress instead of repeating the same failure).
        try
        {
            await Collection.InsertManyAsync(items, new InsertManyOptions { IsOrdered = false }, cancellationToken);
        }
        catch (MongoBulkWriteException<CveMongoModel> e) when (e.WriteErrors.All(IsDuplicateKeyError))
        {
            // Every error is a duplicate key: another worker inserted these CVEs first.
        }

        return items;
    }

    private static bool IsDuplicateKeyError(BulkWriteError error)
    {
        return error.Category == ServerErrorCategory.DuplicateKey;
    }

    public async Task CreateOrUpdateExisting(IList<CveMongoModel> items, CancellationToken cancellationToken = default)
    {
        var bulkModels = items
            .Select(s => new ReplaceOneModel<CveMongoModel>(
                Builders<CveMongoModel>.Filter.Eq(c => c.CveId, s.CveId),
                s)
            {
                IsUpsert = true
            });

        await Collection.BulkWriteAsync(bulkModels, cancellationToken: cancellationToken);
    }

    public async Task<IList<string>> GetExistingCveIds(IEnumerable<string> cveIds, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CveMongoModel>.Filter.In(c => c.CveId, cveIds.Distinct());
        var existing = await Collection.Find(filter)
            .Project(s => s.CveId)
            .ToListAsync(cancellationToken);

        return existing;
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

    public async Task<long> CountCves(string vendor, string product, CancellationToken cancellationToken = default)
    {
        var filter = GetVendorProductFilter(vendor, product);

        return await Collection.CountDocumentsAsync(filter, cancellationToken: cancellationToken);
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
