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

    [Fact]
    public void Cve_WhenCvss3HasNullBaseScore_FallsBackToCvss31()
    {
        // Non-trivial rule: the fallback triggers not only when Cvss3 is null, but also when
        // Cvss3 exists yet has no base score — the 3.1 metric is then used instead.
        var source = new CveMongoModel
        {
            CveId = "CVE-Z",
            Cvss3 = new CvssThree { Version = "3.0", BaseSeverity = "CRITICAL" },
            Cvss31 = new CvssThree { Version = "3.1", BaseScore = 6.5, BaseSeverity = "HIGH" },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        vm.Cvss3!.Version.Should().Be("3.1");
        vm.Cvss3.BaseScore.Should().Be(6.5);
        vm.Cvss3.BaseSeverity.Should().Be("HIGH");
    }

    [Fact]
    public void Cve_Cwes_FlattensEveryWeaknessEntryIntoOneArray()
    {
        var source = new CveMongoModel
        {
            CveId = "CVE-Z",
            Cwes = new[]
            {
                new ProblemData { Cwes = new[] { "CWE-502", "CWE-78" } },
                new ProblemData { Cwes = new[] { "CWE-20" } },
            },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        vm.Cwes.Should().Equal("CWE-502", "CWE-78", "CWE-20");
    }

    [Fact]
    public void Cve_ReferencesUrls_ProjectsUrlInPayloadOrder()
    {
        var source = new CveMongoModel
        {
            CveId = "CVE-Z",
            References = new[]
            {
                new Reference { Url = "https://example.com/b", Name = "second" },
                new Reference { Url = "https://example.com/a", Name = "first" },
            },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        // Non-trivial rule: only Url is projected (Name/Refsource/Tags are dropped),
        // in the payload order — NOT re-sorted.
        vm.ReferencesUrls.Should().Equal("https://example.com/b", "https://example.com/a");
    }

    [Fact]
    public void Cve_VulnerableConfigurations_ProjectsCpeUriOnly()
    {
        var source = new CveMongoModel
        {
            CveId = "CVE-Z",
            VulnerableConfigurations = new[]
            {
                new CpeTwoThree { CpeUri = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", Vulnerable = true, VersionEndExcluding = "1.1" },
            },
        };

        var vm = CreateMapper().Map<CveViewModel>(source);

        // Non-trivial rule: the version-range properties are dropped, only the URI stays.
        vm.VulnerableConfigurations.Should().Equal("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*");
    }
}
