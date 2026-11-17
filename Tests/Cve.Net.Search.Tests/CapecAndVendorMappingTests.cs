using Cve.Net.Search.Domain.Database.MongoModels;
using Cve.Net.Search.Domain.Database.MongoModels.Capec;
using Cve.Net.Search.Domain.ViewModels;
using CVESearch.Mapping;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

public class CapecAndVendorMappingTests
{
    [Fact]
    public void Capec_AllProperties_MapByName()
    {
        // Convention mapping: every ViewModel member maps by name from the Mongo model.
        var source = new CapecMongoModel
        {
            Name = "Spam",
            CapecId = "1",
            Summary = "sum",
            Prerequisites = new[] { "p" },
            Solutions = new[] { "s" },
            RelatedCapecs = new[] { "2" },
            RelatedCwes = new[] { "79" },
            Severity = "High",
            Taxonomy = new Cve.Net.Search.Domain.Common.Capec.Taxonomy[0],
            LikelyhoodAttack = "L",
            ExecutionFlowTypeAttacks = new Cve.Net.Search.Domain.Common.Capec.ExecutionFlowTypeAttack[0],
        };

        var vm = source.ToCapecViewModel();

        vm.Should().BeEquivalentTo(new CapecViewModel
        {
            Name = "Spam",
            CapecId = "1",
            Summary = "sum",
            Prerequisites = new[] { "p" },
            Solutions = new[] { "s" },
            RelatedCapecs = new[] { "2" },
            RelatedCwes = new[] { "79" },
            Severity = "High",
            Taxonomy = source.Taxonomy,
            LikelyhoodAttack = "L",
            ExecutionFlowTypeAttacks = source.ExecutionFlowTypeAttacks,
        });
    }

    [Fact]
    public void Capec_NullArrays_MapToNull()
    {
        // Convention: missing collections map to null (never empty arrays).
        var vm = new CapecMongoModel { CapecId = "1" }.ToCapecViewModel();

        vm.Prerequisites.Should().BeNull();
        vm.Taxonomy.Should().BeNull();
        vm.ExecutionFlowTypeAttacks.Should().BeNull();
    }

    [Fact]
    public void Vendor_Softwares_ListMapsToArray()
    {
        // Convention: persistence stores a List, the wire contract exposes an array.
        var source = new VendorProductsMongoModel
        {
            Vendor = "acme",
            Softwares = new List<string> { "widget", "gadget" },
        };

        var vm = source.ToVendorProductsViewModel();

        vm.Vendor.Should().Be("acme");
        vm.Softwares.Should().Equal("widget", "gadget");
    }

    [Fact]
    public void Vendor_NullSoftwares_MapsToNull()
    {
        var vm = new VendorProductsMongoModel { Vendor = "acme" }.ToVendorProductsViewModel();

        vm.Softwares.Should().BeNull();
    }
}
