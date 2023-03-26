using Cve.Application.Services;
using Cve.DomainModels.MongoModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cve.Infrastructure.Services
{
    public class CveMongoService : ICveMongoService
    {
        public async Task SaveItemToDatabase(CveMongoModel item)
        {
            // Todo: implement
        }
    }
}
