namespace Cve.Net.Search.Domain.ViewModels
{
    /// <summary>
    /// Vendor with products
    /// </summary>
    public class VendorProductsViewModel
    {
        /// <summary>
        /// Vendor name
        /// </summary>
        public string Vendor { get; set; }

        /// <summary>
        /// Products
        /// </summary>
        public string[] Softwares { get; set; }
    }
}
