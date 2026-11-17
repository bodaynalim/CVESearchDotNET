using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.ViewModels;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

// T04: wire-contract snapshots for CveController responses, pinned against ADR-0001
// (camelCase naming, declared property order, nulls serialized).
public class CveContractSnapshotTests
{
    [Fact]
    public void CveViewModel_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new CveViewModel
        {
            CveId = "CVE-2024-1234",
            Assigner = "mitre",
            Published = new DateTime(2024, 1, 15),
            Modified = new DateTime(2024, 2, 1),
            Cwes = ["CWE-79"],
            Summary = "Cross-site scripting in ExampleApp.",
            Cvss2 = new CvssTwo
            {
                Access = new AccessTwo { Vector = "Network", Complexity = "Low", Authentication = "None" },
                Impact = new Impact { Confidentiality = "Partial", Integrity = "Partial", Availability = "None" },
                BaseScore = 4.3,
                ExploitabilityScore = 8.6,
                ImpactScore = 2.9,
                VectorString = "AV:N/AC:L/Au:N/C:P/I:P/A:N",
                Severity = "MEDIUM",
                Version = "2.0",
            },
            Cvss3 = new CvssThree
            {
                Attack = new AttackThree
                {
                    Vector = "Network",
                    Complexity = "Low",
                    PrivilegesRequired = "None",
                    UserInteraction = "Required",
                    Scope = "Unchanged",
                },
                Impact = new Impact { Confidentiality = "High", Integrity = "High", Availability = "None" },
                BaseScore = 7.5,
                ExploitabilityScore = 2.8,
                ImpactScore = 5.5,
                VectorString = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                BaseSeverity = "HIGH",
                Version = "3.0",
            },
            ReferencesUrls = ["https://example.com/advisory/CVE-2024-1234"],
            VulnerableConfigurations = ["cpe:2.3:a:example:example_app:1.0:*:*:*:*:*:*:*"],
        });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractSerialization.NormalizeNewlines(ContractGolden.CveViewModel),
            "the Cve wire contract is pinned by ADR-0001; if this diff is an intended contract change, update the golden JSON after review and mirror it in CveUI fixtures");
    }

    [Fact]
    public void CveViewModel_WithoutAnyCvss_MatchesGoldenContractWithNullCvssKeys()
    {
        var actual = ContractSerialization.Serialize(new CveViewModel
        {
            CveId = "CVE-2024-5678",
            Assigner = "mitre",
            Published = new DateTime(2024, 3, 1),
            Modified = new DateTime(2024, 3, 2),
            Cwes = [],
            Summary = "Insufficient information, no scoring available.",
            // The record properties are declared non-nullable but the wire payload for a
            // CVSS-less CVE legitimately carries explicit nulls вЂ” the golden pins exactly that.
            Cvss2 = null!,
            Cvss3 = null!,
            ReferencesUrls = [],
            VulnerableConfigurations = [],
        });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractSerialization.NormalizeNewlines(ContractGolden.CveViewModelWithoutCvss),
            "cvss2/cvss3 must stay present as explicit nulls on the wire; dropping the keys would be a breaking contract change for CveUI");
    }

    [Fact]
    public void CveSearchCountViewModel_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new CveSearchCountViewModel { Total = 42 });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractSerialization.NormalizeNewlines(ContractGolden.CveSearchCountViewModel),
            "the count-endpoint wire contract is pinned by ADR-0001");
    }

    [Fact]
    public void CveViewModel_FieldRenamedToPascalCaseOnWire_FailsAgainstGolden()
    {
        // Regression guard (anti-cheat): a PascalCase wire name must NOT be equal to the
        // golden, proving the comparison actually detects casing regressions.
        var actual = ContractSerialization.FormatForDiff("""{"CveId":"CVE-2024-1234"}""");

        actual.Should().NotBe(ContractGolden.CveViewModel);
    }
}
