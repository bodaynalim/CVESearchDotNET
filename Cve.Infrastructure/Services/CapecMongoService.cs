using Cve.Application.Services;
using Cve.DomainModels.MongoModels;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public class CapecMongoService : BaseMongoService<CapecMongoModel>, ICapecMongoService
    {
        public CapecMongoService(IMongoDatabase db) : base(db, "Capecs")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Ascending(c => c.CapecId)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCapecs)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CapecMongoModel>(Builders<CapecMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)));
        }
    }
}
