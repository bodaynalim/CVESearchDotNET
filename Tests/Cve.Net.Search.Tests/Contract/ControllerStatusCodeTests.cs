using System.Net;
using System.Net.Http.Json;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

// T04: status-code coverage over the WebApplicationFactory seam (see ApiFactory for the
// stubbing rationale). NotFound messages are pinned because CODING_STANDARDS section 7
// requires human-meaningful messages; the 200/400/405 cases pin the [ApiController]
// validation and method-matching behavior implied by the route conventions.
public class ControllerStatusCodeTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;

    public ControllerStatusCodeTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Cve_Get_UnknownId_Returns404WithNotFoundMessage()
    {
        var response = await _factory.CreateClient().GetAsync("/cve/CVE-0000-0000");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadAsStringAsync()).Should().Contain("CVE-0000-0000 is not found");
    }

    [Fact]
    public async Task Cve_Get_KnownId_Returns200WithCamelCaseCveIdOnTheWire()
    {
        var client = _factory.CreateClientWithCve(new CveMongoModel { CveId = "CVE-0000-0001" });

        var response = await client.GetAsync("/cve/CVE-0000-0001");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        json.TryGetProperty("cveId", out var cveId).Should().BeTrue(
            "ADR-0001: the wire contract is camelCase even though the C# record property is CveId");
        cveId.GetString().Should().Be("CVE-0000-0001");
    }

    [Fact]
    public async Task Cwe_Get_UnknownId_Returns404WithNotFoundMessage()
    {
        var response = await _factory.CreateClient().GetAsync("/cwe/99999");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadAsStringAsync()).Should().Contain("CWE-99999 is not found");
    }

    [Fact]
    public async Task Cwe_CountAll_Returns200WithCamelCaseTotalJson()
    {
        var response = await _factory.CreateClient().GetAsync("/cwe/all/count");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        json.TryGetProperty("total", out var total).Should().BeTrue(
            "ADR-0001: the wire contract is camelCase even though the C# record property is Total");
        total.GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Cwe_Get_NonNumericId_Returns400()
    {
        var response = await _factory.CreateClient().GetAsync("/cwe/not-a-number");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Capec_Get_UnknownId_Returns404WithNotFoundMessage()
    {
        var response = await _factory.CreateClient().GetAsync("/capec/99999");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadAsStringAsync()).Should().Contain("CAPEC-99999 is not found");
    }

    [Fact]
    public async Task Vendors_GetProductsByVendor_UnknownVendor_Returns404WithNotFoundMessage()
    {
        var response = await _factory.CreateClient().GetAsync("/vendors/unknown");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadAsStringAsync()).Should().Contain("unknown is not found");
    }

    [Fact]
    public async Task Cve_GetAll_CountOutOfRange_Returns400()
    {
        // {count} is [Range(1, int.MaxValue)]: 0 fails validation → 400 before any service call.
        var response = await _factory.CreateClient().GetAsync("/cve/all/0/1/false/true");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Cwe_CountAll_PostToGetOnlyEndpoint_Returns405()
    {
        var response = await _factory.CreateClient().PostAsync("/cwe/all/count", content: null);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }
}
