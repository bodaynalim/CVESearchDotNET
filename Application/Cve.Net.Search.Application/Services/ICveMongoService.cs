using Cve.Net.Search.Domain.Database.MongoModels.Cve;

namespace Cve.Application.Services
{
    public interface ICveMongoService : IBaseMongoService<CveMongoModel>
    {
        /// <summary>
        /// Get CVEs list for specific vendor and product
        /// </summary>
        /// <param name="vendor">Vendor</param>
        /// <param name="product">Product</param>
        /// <param name="count">Count</param>
        /// <param name="page">Page</param>
        /// <param name="descending">True if order by descending</param>
        /// <param name="byPublished">True if order by published date (else by modified date)</param>
        /// <returns></returns>
        Task<IList<CveMongoModel>> GetCveList(string vendor, string product, int count,
            int page, bool descending, bool byPublished = true);

        Task<CveMongoModel> GetLastOnePublished(string vendor, string product);

        Task<CveMongoModel> GetLastOneModified(string vendor, string product);
    }
}
