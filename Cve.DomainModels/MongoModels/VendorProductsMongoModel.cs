using System.Collections.Generic;

namespace Cve.DomainModels.MongoModels
{
    public class VendorProductsMongoModel : BaseMongoModel
    {
        public string Vendor { get; set; }

        public List<string> Softwares { get; set; }
    }
}
