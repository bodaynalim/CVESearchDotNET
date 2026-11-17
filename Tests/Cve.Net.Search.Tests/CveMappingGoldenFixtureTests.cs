using AutoMapper;
using Cve.Infrastructure.AutoMapper;
using Cve.Infrastructure.Extensions;
using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels.NVDApi.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Domain.ViewModels;
using FluentAssertions;
using Newtonsoft.Json;
using Xunit;
using Reference = Cve.Net.Search.Domain.Database.MongoModels.Cve.Reference;

namespace Cve.Net.Search.Tests;

/// <summary>
/// T03 — Golden CVE mapping fixture.
///
/// The fixture (Fixtures/cve-golden-nvd-api.json) is the unmodified <c>vulnerabilities[0]</c>
/// element captured from the real NVD API 2.0 endpoint
/// https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0001 (pretty-printed only,
/// no values edited). The expected domain objects below were authored by hand from the mapping
/// rules in <see cref="ToMongoModelExtensions"/> and <see cref="VulnerabilitiesProfile"/> —
/// they are NOT snapshots of the current output. If one of these tests fails with a specific
/// field difference, the mapping (or its rules) has changed and the golden expectation must be
/// reviewed deliberately.
///
/// Edge-case trade-off of the real record (CVE-1999-0001): it naturally covers missing fields
/// (no CVSS v3/v3.1 metrics, no vendorComments, references without "tags"), 0-element arrays
/// (references carry no tags → empty after mapping) and 1/many-element arrays (weaknesses,
/// descriptions, 23 cpeMatch entries). It does NOT cover: special characters in the FIRST
/// description (only the Spanish one has accents — but Summary takes just the first
/// description, so they never reach the domain model), a non-vulnerable cpeMatch, and
/// version-range CPE properties. Those remain covered by the in-code tests in
/// CveMappingTests.
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
        cve.Cve.References.Should().HaveCount(4);
        cve.Cve.References.Should().OnlyContain(r => r.Tags == null, "real NVD references here carry no tags at all");
        cve.Cve.Weaknesses.Should().HaveCount(1);
        cve.Cve.Metrics!.CvssMetricV2.Should().HaveCount(1);
        cve.Cve.Metrics.CvssMetricV30.Should().BeNull("the record has no CVSS 3.0 metric");
        cve.Cve.Metrics.CvssMetricV31.Should().BeNull("the record has no CVSS 3.1 metric");
        cve.Cve.Configurations.Should().HaveCount(1);
        cve.Cve.Configurations!.Single().Nodes.Should().HaveCount(1);
        cve.Cve.Configurations!.Single().Nodes!.Single().CpeMatch.Should().HaveCount(23);
        cve.Cve.Configurations!.Single().Nodes!.Single().CpeMatch.Should().OnlyContain(c => c.Vulnerable);

        // Fields intentionally absent from the payload (missing fields must map to defaults/nulls):
        cve.Cve.VendorComments.Should().BeNull();
    }

    [Fact]
    public void GoldenCve_MapsToExpectedMongoModel()
    {
        // Non-trivial rule: the pre-2016 NVD payload has NO UTC offset in the timestamps, so
        // DateTimeOffset (and therefore .UtcDateTime) is resolved against the machine's local
        // timezone — the expectation deliberately mirrors the production parse rule instead of
        // hard-coding a magic instant.
        var expectedPublished = DateTimeOffset.Parse("1999-12-30T05:00:00.000").UtcDateTime;
        var expectedModified = DateTimeOffset.Parse("2026-06-16T21:47:13.977").UtcDateTime;

        var expected = new CveMongoModel
        {
            CveId = "CVE-1999-0001",
            Assigner = "cve@mitre.org",
            Published = expectedPublished,
            Modified = expectedModified,
            // Non-trivial rule: every weakness entry becomes one ProblemData with its CWE id(s).
            Cwes = new[]
            {
                new ProblemData { Cwes = new[] { "CWE-20" } },
            },
            // Non-trivial rule: Summary is ONLY the first description of the payload, regardless
            // of language; the Spanish one is dropped (not joined).
            Summary = "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.",
            Cvss2 = new CvssTwo
            {
                Access = new AccessTwo { Vector = "NETWORK", Complexity = "LOW", Authentication = "NONE" },
                VectorString = "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                BaseScore = 5.0,
                ExploitabilityScore = 10.0,
                ImpactScore = 2.9,
                Impact = new Impact { Availability = "PARTIAL", Confidentiality = "NONE", Integrity = "NONE" },
                // Non-obvious: Version/enum-to-string uses plain Enum.ToString(), and the generated
                // enum member for CVSS "2.0" is named `_2_0`, so the domain string is "_2_0" (not "2.0").
                Version = "_2_0",
                // Non-trivial rule: CVSS v2 Severity comes from the metric's flat baseSeverity field,
                // NOT from CvssData (the v2 cvssData has no baseSeverity).
                Severity = "MEDIUM",
            },
            Cvss3 = null, // Real edge case: a CVE with no CVSS v3 metric at all.
            Cvss31 = null,
            // Non-trivial rules: Name is filled from the URL (NVD API has no separate name),
            // Refsource from "source"; tags are absent in the payload → empty arrays, NOT null.
            References = new[]
            {
                new Reference { Url = "http://www.openbsd.org/errata23.html#tcpfix", Name = "http://www.openbsd.org/errata23.html#tcpfix", Refsource = "cve@mitre.org", Tags = Array.Empty<string>() },
                new Reference { Url = "http://www.osvdb.org/5707", Name = "http://www.osvdb.org/5707", Refsource = "cve@mitre.org", Tags = Array.Empty<string>() },
                new Reference { Url = "http://www.openbsd.org/errata23.html#tcpfix", Name = "http://www.openbsd.org/errata23.html#tcpfix", Refsource = "af854a3a-2127-422b-91ae-364da2661108", Tags = Array.Empty<string>() },
                new Reference { Url = "http://www.osvdb.org/5707", Name = "http://www.osvdb.org/5707", Refsource = "af854a3a-2127-422b-91ae-364da2661108", Tags = Array.Empty<string>() },
            },
            // Non-trivial rule: every cpeMatch is vulnerable here, so all 23 URIs survive, in payload order.
            VulnerableConfigurations = new[]
            {
                new CpeTwoThree { CpeUri = "cpe:2.3:o:bsdi:bsd_os:3.1:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:1.1:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:1.1.5.1:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:1.2:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.0:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.0.1:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.0.5:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.1.5:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.1.6:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.1.6.1:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.1.7:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.1.7.1:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2.2:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2.3:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2.4:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2.5:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2.6:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:2.2.8:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:freebsd:freebsd:3.0:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:openbsd:openbsd:2.3:*:*:*:*:*:*:*", Vulnerable = true },
                new CpeTwoThree { CpeUri = "cpe:2.3:o:openbsd:openbsd:2.4:*:*:*:*:*:*:*", Vulnerable = true },
            },
            // Non-trivial rule: CPE URIs are split by ':' (empty segments removed) and grouped by
            // vendor → software; the OS/bitness segments here are the literal "*" (RemoveEmptyEntries
            // does NOT collapse '*' into empty), so Version/Os/Bitness is "3.1"/"*"/"*" etc.
            // Real edge case: one vendor ("bsdi") with a single product/version (1-element arrays).
            Products = new[]
            {
                new VulnerableProducts
                {
                    Vendor = "bsdi",
                    Softwares = new[]
                    {
                        new SoftwareWithVersions
                        {
                            SoftwareName = "bsd_os",
                            Versions = new[] { new VersionOs { Version = "3.1", Os = "*", Bitness = "*" } },
                        },
                    },
                },
                new VulnerableProducts
                {
                    Vendor = "freebsd",
                    Softwares = new[]
                    {
                        new SoftwareWithVersions
                        {
                            SoftwareName = "freebsd",
                            Versions = new[]
                            {
                                new VersionOs { Version = "1.0", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "1.1", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "1.1.5.1", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "1.2", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.0", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.0.1", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.0.5", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.1.5", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.1.6", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.1.6.1", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.1.7", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.1.7.1", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2.2", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2.3", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2.4", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2.5", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2.6", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.2.8", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "3.0", Os = "*", Bitness = "*" },
                            },
                        },
                    },
                },
                new VulnerableProducts
                {
                    Vendor = "openbsd",
                    Softwares = new[]
                    {
                        new SoftwareWithVersions
                        {
                            SoftwareName = "openbsd",
                            Versions = new[]
                            {
                                new VersionOs { Version = "2.3", Os = "*", Bitness = "*" },
                                new VersionOs { Version = "2.4", Os = "*", Bitness = "*" },
                            },
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
        var expectedPublished = DateTimeOffset.Parse("1999-12-30T05:00:00.000").UtcDateTime;
        var expectedModified = DateTimeOffset.Parse("2026-06-16T21:47:13.977").UtcDateTime;

        var expected = new CveViewModel
        {
            CveId = "CVE-1999-0001",
            Assigner = "cve@mitre.org",
            Published = expectedPublished,
            Modified = expectedModified,
            // Non-trivial rule: the ProblemData wrappers are flattened away — every CWE id of
            // every weakness entry is collected into one flat string array.
            Cwes = new[] { "CWE-20" },
            Summary = "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.",
            // Non-trivial rule: ReferencesUrls is a pure projection of Reference.Url in payload
            // order — including the duplicated URLs the real record carries.
            ReferencesUrls = new[]
            {
                "http://www.openbsd.org/errata23.html#tcpfix",
                "http://www.osvdb.org/5707",
                "http://www.openbsd.org/errata23.html#tcpfix",
                "http://www.osvdb.org/5707",
            },
            // Non-trivial rule: only the CPE URI string is projected from VulnerableConfigurations.
            VulnerableConfigurations = new[]
            {
                "cpe:2.3:o:bsdi:bsd_os:3.1:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:1.1:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:1.1.5.1:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:1.2:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.0:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.0.1:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.0.5:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.1.5:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.1.6:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.1.6.1:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.1.7:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.1.7.1:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2.2:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2.3:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2.4:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2.5:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2.6:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:2.2.8:*:*:*:*:*:*:*",
                "cpe:2.3:o:freebsd:freebsd:3.0:*:*:*:*:*:*:*",
                "cpe:2.3:o:openbsd:openbsd:2.3:*:*:*:*:*:*:*",
                "cpe:2.3:o:openbsd:openbsd:2.4:*:*:*:*:*:*:*",
            },
            Cvss2 = new CvssTwo
            {
                Access = new AccessTwo { Vector = "NETWORK", Complexity = "LOW", Authentication = "NONE" },
                VectorString = "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                BaseScore = 5.0,
                ExploitabilityScore = 10.0,
                ImpactScore = 2.9,
                Impact = new Impact { Availability = "PARTIAL", Confidentiality = "NONE", Integrity = "NONE" },
                Version = "_2_0",
                Severity = "MEDIUM",
            },
            Cvss3 = null, // Real edge case: no CVSS v3 metric in the record → the view model exposes null.
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

        viewModel.CveId.Should().Be("CVE-1999-0001");
        viewModel.Cwes.Should().Equal("CWE-20");
        viewModel.Cvss2!.Version.Should().Be("_2_0", "enum names in the generated NVD types are not the wire values");
        viewModel.Cvss2!.Severity.Should().Be("MEDIUM");
        viewModel.Cvss3.Should().BeNull("a record without CVSS v3 metrics must not produce a phantom metric");
        viewModel.VulnerableConfigurations.Should().HaveCount(23);
        viewModel.ReferencesUrls.Should().HaveCount(4);
    }
}
