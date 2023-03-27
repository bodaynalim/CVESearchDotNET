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
    public class CveMongoService : BaseMongoService<CveMongoModel>, ICveMongoService
    {
        public CveMongoService(IMongoDatabase db) : base(db, "Cves")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.CveId)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Published)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Descending(c => c.Modified)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.Products)));
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveMongoModel>(Builders<CveMongoModel>.IndexKeys.Ascending(c => c.VulnerableConfigurations)));
        }
    }
}
