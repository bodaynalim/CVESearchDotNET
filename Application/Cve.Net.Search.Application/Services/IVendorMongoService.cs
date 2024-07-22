using Cve.Net.Search.Domain.Database.MongoModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;

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

        /// <summary>
        /// Get vendors by search parameters
        /// </summary>
        /// <param name="search">Search parameter</param>
        /// <param name="take">Amount to take</param>
        /// <returns></returns>
        IEnumerable<string> GetAllVendors(string search, int take);
    }
}
