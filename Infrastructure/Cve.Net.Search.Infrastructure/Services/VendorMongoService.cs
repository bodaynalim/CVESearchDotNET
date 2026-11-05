using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services;

public class VendorMongoService : BaseMongoService<VendorProductsMongoModel>, IVendorMongoService, IIndexInitializer
{
    public VendorMongoService(IMongoDatabase db) : base(db, "Vendors")
    {
    }

    public async Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        var options = new CreateIndexOptions() { Unique = true };
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<VendorProductsMongoModel>(Builders<VendorProductsMongoModel>.IndexKeys.Ascending(c => c.Vendor), options), cancellationToken: cancellationToken);
        await Collection.Indexes.CreateOneAsync(new CreateIndexModel<VendorProductsMongoModel>(Builders<VendorProductsMongoModel>.IndexKeys.Descending(c => c.Softwares)), cancellationToken: cancellationToken);
    }

    public async Task BulkUpsertVendors(IList<(string Vendor, IReadOnlyList<string> Softwares)> vendorProducts, CancellationToken cancellationToken = default)
    {
        if (vendorProducts.Count == 0)
            return;

        var bulkModels = vendorProducts
            .Where(vp => !string.IsNullOrEmpty(vp.Vendor))
            .GroupBy(vp => vp.Vendor)
            .Select(g => new UpdateOneModel<VendorProductsMongoModel>(
                Builders<VendorProductsMongoModel>.Filter.Eq(x => x.Vendor, g.Key),
                Builders<VendorProductsMongoModel>.Update.AddToSetEach(x => x.Softwares, g.SelectMany(s => s.Softwares).Distinct().ToList()))
            {
                IsUpsert = true
            });

        // IsOrdered:false + duplicate-key tolerance: two concurrent importers can race on
        // the unique Vendor index during the upsert insert path; the loser of the race
        // is already handled by the winner's insert.
        try
        {
            await Collection.BulkWriteAsync(bulkModels, new BulkWriteOptions { IsOrdered = false }, cancellationToken);
        }
        catch (MongoBulkWriteException<VendorProductsMongoModel> e) when (e.WriteErrors.All(w => w.Category == ServerErrorCategory.DuplicateKey))
        {
            // Every error is a duplicate key race on the unique Vendor index.
        }
    }

    public async Task<VendorProductsMongoModel> CreateOrUpdateVendor(VulnerableProducts vendorModel, CancellationToken cancellationToken = default)
    {
        var filter = Builders<VendorProductsMongoModel>.Filter.Eq(x => x.Vendor, vendorModel.Vendor);
        var vendor = await Collection.Find(filter).FirstOrDefaultAsync(cancellationToken);

        var products = vendorModel.Softwares.Select(s => s.SoftwareName).ToList();

        if (vendor == null)
        {
            var newItem = new VendorProductsMongoModel
            {
                Vendor = vendorModel.Vendor,
                Softwares = products
            };

            await Collection.InsertOneAsync(newItem, cancellationToken: cancellationToken);

            return newItem;
        }
        else
        {
            vendor.Softwares.AddRange(products);
            vendor.Softwares = vendor.Softwares.Distinct().ToList();
            var result = await Collection.ReplaceOneAsync(Builders<VendorProductsMongoModel>.Filter.Eq(x => x.Id, vendor.Id), vendor, cancellationToken: cancellationToken);

            return result.IsAcknowledged ? vendor : null;
        }
    }

    public override async Task<VendorProductsMongoModel> CreateOrUpdateExisting(VendorProductsMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.Vendor == item.Vendor).FirstOrDefaultAsync(cancellationToken);

        if (any == null)
            return await CreateNewItem(item, cancellationToken);
        else
        {
            item.Id = any.Id;

            var result = await Collection.ReplaceOneAsync(e => e.Vendor == item.Vendor, item, cancellationToken: cancellationToken);

            return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
        }
    }

    public override async Task<VendorProductsMongoModel> CreateNewItemIfNotExist(VendorProductsMongoModel item, CancellationToken cancellationToken = default)
    {
        var any = await Collection.Find(s => s.Vendor == item.Vendor).FirstOrDefaultAsync(cancellationToken);

        if (any != null)
            return any;

        await Collection.InsertOneAsync(item, cancellationToken: cancellationToken);

        return item;
    }

    public override async Task<VendorProductsMongoModel> Get(string id, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(s => s.Vendor == id).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<IEnumerable<string>> GetAllVendors(CancellationToken cancellationToken = default)
    {
        var filter = FilterDefinition<VendorProductsMongoModel>.Empty;
        var result = await Collection.Find(filter)
            .Project(x => x.Vendor)
            .ToListAsync(cancellationToken);
        return result;
    }

    public async Task<IEnumerable<string>> GetAllVendors(string search, int take, CancellationToken cancellationToken = default)
    {
        var searchToLower = search.ToLower();
        var filter = Builders<VendorProductsMongoModel>.Filter.Regex(x => x.Vendor, new MongoDB.Bson.BsonRegularExpression(searchToLower, "i"));
        var result = await Collection.Find(filter)
            .Limit(take)
            .Project(x => x.Vendor)
            .ToListAsync(cancellationToken);
        return result;
    }
}
