namespace Cve.Net.Search.Domain.ViewModels;

/// <summary>
/// Vendor with products
/// </summary>
public record VendorProductsViewModel
{
    /// <summary>
    /// Vendor name
    /// </summary>
    public string Vendor { get; init; }

    /// <summary>
    /// Products
    /// </summary>
    public string[] Softwares { get; init; }
}
