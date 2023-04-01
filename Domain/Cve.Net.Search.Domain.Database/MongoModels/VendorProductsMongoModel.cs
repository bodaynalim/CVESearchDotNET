using System.Collections.Generic;

namespace Cve.Net.Search.Domain.Database.MongoModels
{
    public class VendorProductsMongoModel : BaseMongoModel
    {
        public string Vendor { get; set; }

        public List<string> Softwares { get; set; }
    }
}
