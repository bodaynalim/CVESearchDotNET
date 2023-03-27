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
    public class CweMongoService : BaseMongoService<CweMongoModel>, ICweMongoService
    {
        public CweMongoService(IMongoDatabase db) : base(db, "Cwes")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CweMongoModel>(Builders<CweMongoModel>.IndexKeys.Ascending(c => c.CweId)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CweMongoModel>(Builders<CweMongoModel>.IndexKeys.Descending(c => c.RelatedCwes)));
        }
    }
}
