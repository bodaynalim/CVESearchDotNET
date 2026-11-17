using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Cve.Net.Search.Domain.Database.MongoModels;

public class BaseMongoModel
{
    /// <inheritdoc />
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; }
}
