using Cve.Net.Search.Domain.Common.Capec;
using Cve.Net.Search.Domain.ViewModels;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

// T04: wire-contract snapshots for CapecController responses, pinned against ADR-0001.
public class CapecContractSnapshotTests
{
    [Fact]
    public void CapecViewModel_SerializedViaMvcNewtonsoftSettings_MatchesGoldenContract()
    {
        var actual = ContractSerialization.Serialize(new CapecViewModel
        {
            Name = "Test Attack Pattern",
            CapecId = "1",
            Summary = "An adversary induces a fault.",
            Prerequisites = ["Access to the target system"],
            Solutions = ["Input validation"],
            RelatedCapecs = ["2"],
            RelatedCwes = ["79"],
            Severity = "High",
            Taxonomy = [new Taxonomy { Name = "ATTACK", EntryId = "1", EntryName = "Test Entry", Url = "https://example.com/capec/1" }],
            LikelyhoodAttack = "Medium",
            ExecutionFlowTypeAttacks =
            [
                new ExecutionFlowTypeAttack
                {
                    Step = "1",
                    Phase = "Explore",
                    DescriptionField = "Adversary probes the target.",
                    Techniques = ["Probe"],
                },
            ],
        });

        ContractSerialization.FormatForDiff(actual).Should().Be(ContractGolden.CapecViewModel,
            "the Capec wire contract is pinned by ADR-0001; note \"techniques\" is the serialized public FIELD of ExecutionFlowTypeAttack and comes first inside the entry (Newtonsoft orders fields before properties)");
    }
}
