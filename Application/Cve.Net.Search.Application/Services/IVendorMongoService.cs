using Cve.Net.Search.Domain.Database.MongoModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Application.Services;

public interface IVendorMongoService : IBaseMongoService<VendorProductsMongoModel>, IIndexInitializer
{
    /// <summary>
    /// Create or update vendor item
    /// </summary>
    /// <param name="vendor">Vendor model</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<VendorProductsMongoModel> CreateOrUpdateVendor(VulnerableProducts vendor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Upsert given vendor/product entries in a single bulk operation: adds every software name
    /// to the vendor's Softwares set, creating the vendor when not existing yet.
    /// </summary>
    /// <param name="vendorProducts">Vendor name to product names map</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task BulkUpsertVendors(IList<(string Vendor, IReadOnlyList<string> Softwares)> vendorProducts, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get all vendors
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IEnumerable<string>> GetAllVendors(CancellationToken cancellationToken = default);

    /// <summary>
    /// Get vendors by search parameters
    /// </summary>
    /// <param name="search">Search parameter</param>
    /// <param name="take">Amount to take</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IEnumerable<string>> GetAllVendors(string search, int take, CancellationToken cancellationToken = default);
}
