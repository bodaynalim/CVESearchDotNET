using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace Cve.DomainModels.MongoModels
{
    public class BaseMongoModel
    {
        /// <inheritdoc />
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
    }
}
