using Cve.Application.Services;
using Cve.DomainModels.MongoModels;
using Cve.DomainModels.MongoModels.Cve;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public class VendorMongoService : BaseMongoService<VendorProductsMongoModel>, IVendorMongoService
    {
        public VendorMongoService(IMongoDatabase db) : base(db, "Vendors")
        {
            var options = new CreateIndexOptions() { Unique = true };
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<VendorProductsMongoModel>(Builders<VendorProductsMongoModel>.IndexKeys.Ascending(c => c.Vendor), options));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<VendorProductsMongoModel>(Builders<VendorProductsMongoModel>.IndexKeys.Descending(c => c.Softwares)));
        }

        public async Task<VendorProductsMongoModel> CreateOrUpdateVendor(VulnarableProducts vendorModel)
        {
            var filter = Builders<VendorProductsMongoModel>.Filter.Eq(x => x.Vendor, vendorModel.Vendor);
            var vendor = await Collection.Find(filter).FirstOrDefaultAsync();

            var products = vendorModel.Softwares.Select(s => s.SoftwareName).ToList();

            if (vendor == null)
            {
                var newItem = new VendorProductsMongoModel
                {
                    Vendor = vendorModel.Vendor,
                    Softwares = products
                };

                await Collection.InsertOneAsync(newItem);

                return newItem;
            }
            else
            {
                vendor.Softwares.AddRange(products);
                vendor.Softwares = vendor.Softwares.Distinct().ToList();
                var result = await Collection.ReplaceOneAsync(Builders<VendorProductsMongoModel>.Filter.Eq(x => x.Id, vendor.Id), vendor);

                return result.IsAcknowledged ? vendor : null;
            }
        }

        public override async Task<VendorProductsMongoModel> CreateOrUpdateExisting(VendorProductsMongoModel item)
        {
            var any = await Collection.Find(s => s.Vendor == item.Vendor).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                var result = await Collection.DeleteOneAsync(e => e.Vendor == item.Vendor);

                return result.IsAcknowledged && result.DeletedCount > 0 ? await CreateNewItem(item) : any;
            }
        }

        public override async Task<VendorProductsMongoModel> CreateNewItemIfNotExist(VendorProductsMongoModel item)
        {
            var any = await Collection.Find(s => s.Vendor == item.Vendor).FirstOrDefaultAsync();

            if (any != null)
                return any;

            await Collection.InsertOneAsync(item);

            return item;
        }

        public override async Task<VendorProductsMongoModel> Get(string id)
        {
            return await Collection.Find(s => s.Vendor == id).FirstOrDefaultAsync();
        }

        public IEnumerable<string> GetAllVendors()
        {
            return Collection.AsQueryable().Select(s => s.Vendor);
        }
    }
}
