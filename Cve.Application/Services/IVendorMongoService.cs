using Cve.DomainModels.MongoModels;

namespace Cve.Application.Services
{
    public interface IVendorMongoService : IBaseMongoService<VendorProductsMongoModel>
    {
        /// <summary>
        /// Create or update vendor item
        /// </summary>
        /// <param name="vendor">Vendor model</param>
        /// <returns></returns>
        Task<VendorProductsMongoModel> CreateOrUpdateVendor(VulnarableProducts vendor);
    }
}
