using CVESearch.CveXmlJsonModels;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Collections;
using System.Collections.Generic;

namespace CVESearch.MongoModels
{
    public class CweMongoModel : BaseMongoModel
    {
        public int CweId { get; set; }

        public string Name { get; set; }

        public StatusEnumeration Status { get; set; }

        public AbstractionEnumeration Abstraction { get; set; }

        public ICollection<int> RelatedCwe { get; set; }
    }
}
