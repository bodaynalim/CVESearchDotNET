using Cve.Net.Search.Domain.Database.CveXmlJsonModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cwe;
using Cve.Net.Search.Domain.ViewModels;
using CVESearch.Mapping;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

public class CweMappingTests
{
    [Fact]
    public void Cwe_EnumToString_ConvertsStatusAndAbstractionToMemberNames()
    {
        // Non-trivial rule: the two enumeration members reach the wire contract as their
        // enum member names via ToString() (not the numeric value, not the XML display form).
        var source = new CweMongoModel
        {
            CweId = "79",
            Status = StatusEnumeration.Draft,
            Abstraction = AbstractionEnumeration.Base,
        };

        var vm = source.ToCweViewModel();

        vm.Status.Should().Be("Draft");
        vm.Abstraction.Should().Be("Base");
    }

    [Fact]
    public void Cwe_AllProperties_MapByName()
    {
        var source = new CweMongoModel
        {
            CweId = "79",
            Name = "XSS",
            Description = "desc",
            RelatedCwes = new[] { "CWE-80" },
        };

        var vm = source.ToCweViewModel();

        vm.CweId.Should().Be("79");
        vm.Name.Should().Be("XSS");
        vm.Description.Should().Be("desc");
        vm.RelatedCwes.Should().Equal("CWE-80");
    }
}
