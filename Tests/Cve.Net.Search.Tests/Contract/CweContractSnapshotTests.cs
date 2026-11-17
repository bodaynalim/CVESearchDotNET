using Cve.Net.Search.Domain.ViewModels;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

// T04: wire-contract snapshots for CweController responses, pinned against ADR-0001.
public class CweContractSnapshotTests
{
    [Fact]
    public void CweViewModel_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new CweViewModel
        {
            CweId = "79",
            Name = "Cross-site Scripting",
            Description = "The product does not neutralize user-controllable input.",
            Status = "Stable",
            Abstraction = "Variant",
            RelatedCwes = ["1004"],
        });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractGolden.CweViewModel,
            "the Cwe wire contract is pinned by ADR-0001; if this diff is an intended contract change, update the golden JSON after review and mirror it in CveUI fixtures");
    }

    [Fact]
    public void CweSearchCountViewModel_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new CweSearchCountViewModel { Total = 319 });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractGolden.CweSearchCountViewModel,
            "the count-endpoint wire contract is pinned by ADR-0001");
    }
}
