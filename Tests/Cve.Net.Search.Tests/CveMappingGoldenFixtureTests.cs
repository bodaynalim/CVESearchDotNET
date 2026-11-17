using AutoMapper;
using Cve.Infrastructure.AutoMapper;
using Cve.Infrastructure.Extensions;
using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels.NVDApi.Cve;
using Cve.Net.Search.Domain.ViewModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Reference = Cve.Net.Search.Domain.Database.MongoModels.Cve.Reference;
using FluentAssertions;
using Newtonsoft.Json;
using Xunit;

namespace Cve.Net.Search.Tests;

/// <summary>
/// T03 — Golden CVE mapping fixture.
///
/// A realistic NVD API 2.0 CVE payload (Fixtures/cve-golden-nvd-api.json) is pinned against
/// explicitly hand-written expected domain objects. The expected values below were authored
/// by hand from the mapping rules in <see cref="ToMongoModelExtensions"/> and
/// <see cref="VulnerabilitiesProfile"/> — they are NOT snapshots of the current output.
/// If one of these tests fails with a specific field difference, the mapping (or its rules)
/// has changed and the golden expectation must be reviewed deliberately.
/// </summary>
public class CveMappingGoldenFixtureTests
{
    private const string FixtureRelativePath = "Fixtures/cve-golden-nvd-api.json";

    private static IMapper CreateMapper() =>
        new MapperConfiguration(cfg => cfg.AddProfile<VulnerabilitiesProfile>()).CreateMapper();

    private static CveItemNewApi LoadGoldenCve()
    {
        var path = Path.Combine(AppContext.BaseDirectory, FixtureRelativePath.Replace('/', Path.DirectorySeparatorChar));
        return JsonConvert.DeserializeObject<CveItemNewApi>(File.ReadAllText(path))!;
    }

    private static CveMongoModel MapGoldenCveToMongoModel() => LoadGoldenCve().ToCveMongoModel().Item1;

    /// <summary>
    /// Array-shape inventory of the fixture — the whole point of it. If any of these change,
    /// the golden expectations below no longer exercise what they claim to exercise.
    /// </summary>
    [Fact]
    public void GoldenFixture_ContainsTheIntendedArrayShapes()
    {
        var cve = LoadGoldenCve();

        cve.Cve.Descriptions.Should().HaveCount(2);
        cve.Cve.References.Should().HaveCount(3);
        cve.Cve.References.Should().Contain(r => r.Tags != null && r.Tags.Count == 0, "an explicit zero-element array");
        cve.Cve.Weaknesses.Should().HaveCount(2);
        cve.Cve.Metrics!.CvssMetricV2.Should().HaveCount(1);
        cve.Cve.Metrics.CvssMetricV30.Should().HaveCount(1);
        cve.Cve.Metrics.CvssMetricV31.Should().HaveCount(1);
        cve.Cve.Configurations.Should().HaveCount(1);
        cve.Cve.Configurations!.Single().Nodes.Should().HaveCount(1);
        cve.Cve.Configurations!.Single().Nodes!.Single().CpeMatch.Should().HaveCount(3);

        // Fields intentionally absent from the payload (missing fields must map to defaults/nulls):
        cve.Cve.VendorComments.Should().BeNull();
        cve.Cve.References.Should().Contain(r => r.Source == null, "a reference without source");
    }

    [Fact]
    public void GoldenCve_MapsToExpectedMongoModel()
    {
        var expected = new CveMongoModel
        {
            CveId = "CVE-2021-45046",
            Assigner = "security@apache.org",
            Published = new DateTime(2021, 12, 13, 16, 15, 9, 333, DateTimeKind.Utc),
            Modified = new DateTime(2024, 11, 21, 6, 27, 13, 587, DateTimeKind.Utc),
            // Every weakness entry is flattened into one ProblemData with its CWE id(s).
            Cwes = new[]
            {
                new ProblemData { Cwes = new[] { "CWE-502" } },
                new ProblemData { Cwes = new[] { "CWE-78" } },
            },
            // Non-trivial rule: Summary is ONLY the first description of the payload,
            // regardless of language; the French one is dropped (not joined).
            Summary = "It was found that log4j & JNDI: <component> permits \"trusted\" lookup chains — café déjà vu",
            Cvss2 = new CvssTwo
            {
                Access = new AccessTwo { Vector = "NETWORK", Complexity = "LOW", Authentication = "NONE" },
                VectorString = "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                BaseScore = 7.5,
                ExploitabilityScore = 10.0,
                ImpactScore = 6.4,
                Impact = new Impact { Availability = "PARTIAL", Confidentiality = "PARTIAL", Integrity = "PARTIAL" },
                // Non-obvious: Version/enum-to-string uses plain Enum.ToString(), and the generated
                // enum member for CVSS "2.0" is named `_2_0`, so the domain string is "_2_0" (not "2.0").
                Version = "_2_0",
                // Non-trivial rule: CVSS v2 Severity comes from the metric's flat baseSeverity field,
                // NOT from CvssData (the v2 cvssData has no baseSeverity).
                Severity = "HIGH",
            },
            // Non-trivial rule: Cvss3 takes cvssMetricV30 (3.0), Cvss31 takes cvssMetricV31 — both are kept.
            Cvss3 = new CvssThree
            {
                Attack = new AttackThree { Vector = "NETWORK", Complexity = "LOW", PrivilegesRequired = "NONE", Scope = "CHANGED", UserInteraction = "NONE" },
                VectorString = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                BaseScore = 9.8,
                ExploitabilityScore = 3.9,
                ImpactScore = 6.0,
                Impact = new Impact { Availability = "HIGH", Confidentiality = "HIGH", Integrity = "HIGH" },
                BaseSeverity = "CRITICAL",
                Version = "_3_0",
            },
            Cvss31 = new CvssThree
            {
                Attack = new AttackThree { Vector = "NETWORK", Complexity = "HIGH", PrivilegesRequired = "LOW", Scope = "UNCHANGED", UserInteraction = "NONE" },
                VectorString = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
                BaseScore = 6.5,
                ExploitabilityScore = 1.8,
                ImpactScore = 3.6,
                Impact = new Impact { Availability = "NONE", Confidentiality = "HIGH", Integrity = "NONE" },
                BaseSeverity = "HIGH",
                Version = "_3_1",
            },
            // Non-trivial rules: Name is filled from the URL (NVD API has no separate name),
            // Refsource from "source", and Tags keeps array shape (empty stays empty).
            References = new[]
            {
                new Reference { Url = "https://logging.apache.org/log4j/2.x/security.html", Name = "https://logging.apache.org/log4j/2.x/security.html", Refsource = "security@apache.org", Tags = Array.Empty<string>() },
                new Reference { Url = "https://nvd.nist.gov/general/cve-process", Name = "https://nvd.nist.gov/general/cve-process", Refsource = null, Tags = Array.Empty<string>() },
                new Reference { Url = "https://www.cve.org/CVERecord?id=CVE-2021-45046", Name = "https://www.cve.org/CVERecord?id=CVE-2021-45046", Refsource = "cna", Tags = new[] { "Vendor Advisory", "Exploit" } },
            },
            // Non-trivial rule: only cpeMatch entries with vulnerable=true survive, in payload order;
            // the version-range properties are carried over; the non-vulnerable Linux kernel entry is dropped.
            VulnerableConfigurations = new[]
            {
                new CpeTwoThree { CpeUri = "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree
                {
                    CpeUri = "cpe:2.3:a:apache:log4j_core:2.14.0:*:*:*:*:*:*:*",
                    Vulnerable = true,
                    VersionStartIncluding = "2.0",
                    VersionEndExcluding = "2.15.0",
                },
            },
            // Non-trivial rule: CPE URIs are split by ':' (empty segments removed) and grouped by
            // vendor → software; the OS/bitness segments here are the literal "*" (RemoveEmptyEntries
            // does NOT collapse '*' into empty), so Version/Os/Bitness is "2.0"/"*"/"*" etc.
            Products = new[]
            {
                new VulnerableProducts
                {
                    Vendor = "apache",
                    Softwares = new[]
                    {
                        new SoftwareWithVersions
                        {
                            SoftwareName = "log4j",
                            Versions = new[] { new VersionOs { Version = "2.0", Os = "*", Bitness = "*" } },
                        },
                        new SoftwareWithVersions
                        {
                            SoftwareName = "log4j_core",
                            Versions = new[] { new VersionOs { Version = "2.14.0", Os = "*", Bitness = "*" } },
                        },
                    },
                },
            },
        };

        var actual = MapGoldenCveToMongoModel();

        actual.Should().BeEquivalentTo(expected, "the golden NVD payload must map to the hand-written domain expectation");
    }

    [Fact]
    public void GoldenCve_MapsToExpectedViewModel()
    {
        var expected = new CveViewModel
        {
            CveId = "CVE-2021-45046",
            Assigner = "security@apache.org",
            Published = new DateTime(2021, 12, 13, 16, 15, 9, 333, DateTimeKind.Utc),
            Modified = new DateTime(2024, 11, 21, 6, 27, 13, 587, DateTimeKind.Utc),
            // Non-trivial rule: the ProblemData wrappers are flattened away — every CWE id of every
            // weakness entry is collected into one flat string array.
            Cwes = new[] { "CWE-502", "CWE-78" },
            Summary = "It was found that log4j & JNDI: <component> permits \"trusted\" lookup chains — café déjà vu",
            // Non-trivial rule: ReferencesUrls is a pure projection of Reference.Url in payload order.
            ReferencesUrls = new[]
            {
                "https://logging.apache.org/log4j/2.x/security.html",
                "https://nvd.nist.gov/general/cve-process",
                "https://www.cve.org/CVERecord?id=CVE-2021-45046",
            },
            // Non-trivial rule: only the CPE URI string is projected from VulnerableConfigurations.
            VulnerableConfigurations = new[]
            {
                "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:apache:log4j_core:2.14.0:*:*:*:*:*:*:*",
            },
            Cvss2 = new CvssTwo
            {
                Access = new AccessTwo { Vector = "NETWORK", Complexity = "LOW", Authentication = "NONE" },
                VectorString = "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                BaseScore = 7.5,
                ExploitabilityScore = 10.0,
                ImpactScore = 6.4,
                Impact = new Impact { Availability = "PARTIAL", Confidentiality = "PARTIAL", Integrity = "PARTIAL" },
                Version = "_2_0",
                Severity = "HIGH",
            },
            // Non-trivial rule: both Cvss3 (3.0) and Cvss31 (3.1) exist in the payload, and Cvss3 —
            // NOT Cvss31 — is what the view model exposes as "Cvss3".
            Cvss3 = new CvssThree
            {
                Attack = new AttackThree { Vector = "NETWORK", Complexity = "LOW", PrivilegesRequired = "NONE", Scope = "CHANGED", UserInteraction = "NONE" },
                VectorString = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                BaseScore = 9.8,
                ExploitabilityScore = 3.9,
                ImpactScore = 6.0,
                Impact = new Impact { Availability = "HIGH", Confidentiality = "HIGH", Integrity = "HIGH" },
                BaseSeverity = "CRITICAL",
                Version = "_3_0",
            },
        };

        var mongoModel = MapGoldenCveToMongoModel();
        var viewModel = CreateMapper().Map<CveViewModel>(mongoModel);

        viewModel.Should().BeEquivalentTo(expected, "the golden NVD payload must reach the view model as hand-written");
    }

    [Fact]
    public void GoldenCve_FullPipeline_ReachesViewModelWithoutManualSteps()
    {
        // Same pipeline the import jobs run: NVD JSON → mongo model → view model.
        var (mongoModel, _) = LoadGoldenCve().ToCveMongoModel();
        var viewModel = CreateMapper().Map<CveViewModel>(mongoModel);

        viewModel.CveId.Should().Be("CVE-2021-45046");
        viewModel.Cwes.Should().Equal("CWE-502", "CWE-78");
        viewModel.Cvss3!.Version.Should().Be("_3_0", "3.0 wins when both 3.0 and 3.1 metrics exist");
        viewModel.Cvss2!.Version.Should().Be("_2_0", "enum names in the generated NVD types are not the wire values");
        viewModel.VulnerableConfigurations.Should()
            .NotContain(c => c.Contains("linux_kernel"), "non-vulnerable cpeMatch entries must be filtered out");
        viewModel.ReferencesUrls.Should().HaveCount(3);
    }
}
