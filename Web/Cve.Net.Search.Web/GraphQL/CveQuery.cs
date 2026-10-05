using Cve.Application.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using HotChocolate.Data;

namespace Cve.Net.Search.Web.GraphQL;

public class CveQuery
{
    [UsePaging]
    [UseProjection]
    [UseFiltering]
    [UseSorting]
    public IExecutable<CveMongoModel> GetCves(ICveMongoService cveService)
    {
        return cveService.AsExecutable();
    }
}
