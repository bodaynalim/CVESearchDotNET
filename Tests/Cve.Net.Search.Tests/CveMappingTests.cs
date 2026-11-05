using AutoMapper;
using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Domain.ViewModels;
using Cve.Infrastructure.AutoMapper;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

public class CveMappingTests
{
    private static IMapper CreateMapper() => new MapperConfiguration(cfg => cfg.AddProfile<VulnerabilitiesProfile>()).CreateMapper();

    [Fact]
    public void Cve_WithOnlyCvss31_FallsBackToCvss31InViewModel()
    {
        var source = new CveMongoModel
        {
            CveId = "CVE-2018-0114",
            Cvss3 = new CvssThree { Version = "3.0" },
            Cvss31 = new CvssThree { Version = "3.1", BaseScore = 7.5, BaseSeverity = "HIGH" },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        vm.Cvss3.Should().NotBeNull();
        vm.Cvss3!.BaseScore.Should().Be(7.5);
        vm.Cvss3.BaseSeverity.Should().Be("HIGH");
    }

    [Fact]
    public void Cve_WithRealCvss30_KeepsCvss30When31AlsoPresent()
    {
        var source = new CveMongoModel
        {
            CveId = "CVE-X",
            Cvss3 = new CvssThree { Version = "3.0", BaseScore = 9.0, BaseSeverity = "CRITICAL" },
            Cvss31 = new CvssThree { Version = "3.1", BaseScore = 8.5, BaseSeverity = "HIGH" },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        vm.Cvss3!.BaseScore.Should().Be(9.0);
    }

    [Fact]
    public void Cve_WithNullCvss3AndCvss31_FallsBackToCvss31InViewModel()
    {
        var source = new CveMongoModel
        {
            CveId = "CVE-2018-0114",
            Cvss3 = null,
            Cvss31 = new CvssThree { Version = "3.1", BaseScore = 7.5, BaseSeverity = "HIGH" },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        vm.Cvss3.Should().NotBeNull();
        vm.Cvss3!.BaseScore.Should().Be(7.5);
    }

    [Fact]
    public void Cve_WithNoCvssAtAll_MapsNull()
    {
        var vm = CreateMapper().Map<CveViewModel>(new CveMongoModel { CveId = "CVE-Y" });

        vm.Cvss3.Should().BeNull();
        vm.Cvss2.Should().BeNull();
    }
}
