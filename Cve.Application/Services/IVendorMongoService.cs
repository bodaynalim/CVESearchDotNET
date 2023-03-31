using Cve.DomainModels.MongoModels;
using Cve.DomainModels.MongoModels.Cve;

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

        /// <summary>
        /// Get all vendors
        /// </summary>
        /// <returns></returns>
        IEnumerable<string> GetAllVendors();
    }
}
