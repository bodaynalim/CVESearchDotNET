using System.Linq;
using Cve.Net.Search.Domain.Database.MongoModels;
using Cve.Net.Search.Domain.ViewModels;

namespace CVESearch.Mapping;

/// <summary>
/// Explicit mapping from the persisted vendor-products Mongo model to the API wire contract.
/// </summary>
public static class VendorProductsMappingExtensions
{
    /// <summary>
    /// Maps a vendor product pair to its <see cref="VendorProductsViewModel"/> wire representation.
    /// </summary>
    public static VendorProductsViewModel ToVendorProductsViewModel(this VendorProductsMongoModel model) => new()
    {
        Vendor = model.Vendor,
        Softwares = model.Softwares?.ToArray(),
    };
}
