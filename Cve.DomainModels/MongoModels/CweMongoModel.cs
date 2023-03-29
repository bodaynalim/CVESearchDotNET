using Cve.DomainModels.CveXmlJsonModels;

namespace Cve.DomainModels.MongoModels
{
    public class CweMongoModel : BaseMongoModel
    {
        public string CweId { get; set; }

        public string Name { get; set; }
        
        public string Description { get; set; }

        public StatusEnumeration Status { get; set; }

        public AbstractionEnumeration Abstraction { get; set; }

        public string[] RelatedCwes { get; set; }
    }
}
