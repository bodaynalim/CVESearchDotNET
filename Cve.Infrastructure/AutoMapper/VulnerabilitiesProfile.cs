using AutoMapper;
using Cve.DomainModels.MongoModels;
using Cve.DomainModels.MongoModels.Capec;
using Cve.DomainModels.MongoModels.Cve;
using Cve.DomainModels.MongoModels.Cwe;
using Cve.DomainModels.ViewModels;
using System.Linq;

namespace Cve.Infrastructure.AutoMapper
{
    public class VulnerabilitiesProfile : Profile
    {
        public VulnerabilitiesProfile()
        {
            CreateMap<CweMongoModel,CweViewModel>()
                .ForMember(m => m.Status, s => s.MapFrom(m => m.Status.ToString()))
                .ForMember(m => m.Abstraction, s => s.MapFrom(m => m.Abstraction.ToString()));

            CreateMap<CapecMongoModel, CapecViewModel>();

            CreateMap<VendorProductsMongoModel, VendorProductsViewModel>();

            CreateMap<CveMongoModel, CveViewModel>()
                 .ForMember(m => m.ReferencesUrls, s => s.MapFrom(m => m.References.Select(r => r.Url).ToArray()))
                 .ForMember(m => m.Cwes, s => s.MapFrom(m => m.Cwes.SelectMany(r => r.Cwes).ToArray()))
                 .ForMember(m => m.VulnerableConfigurations, s => s.MapFrom(m => m.VulnerableConfigurations.Select(r => r.CpeUri).ToArray()));
        }
    }
}
