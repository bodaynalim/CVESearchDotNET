using Cve.Net.Search.Domain.ViewModels;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

// T04: wire-contract snapshots for VendorsController responses, pinned against ADR-0001.
public class VendorsContractSnapshotTests
{
    [Fact]
    public void VendorProductsViewModel_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new VendorProductsViewModel
        {
            Vendor = "example",
            Softwares = ["example_app"],
        });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractGolden.VendorProductsViewModel,
            "the Vendors wire contract is pinned by ADR-0001; if this diff is an intended contract change, update the golden JSON after review and mirror it in CveUI fixtures");
    }

    [Fact]
    public void VendorNameList_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new List<string> { "akamai", "example" });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractGolden.VendorNameList,
            "search/{search} returns a bare JSON string array; wrapping it in an object would break CveUI");
    }
}
