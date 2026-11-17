using System.Reflection;
using System.Text.RegularExpressions;
using CVESearch.Controllers;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Cve.Net.Search.Tests;

// T04: routing-convention snapshots per docs/CODING_STANDARDS.md section 3 and the
// established route style: positional route segments, lowercase templates, and count
// endpoints as separate routes so one count request serves all page turns of a result set.
public class RouteConventionTests
{
    [Fact]
    public void CveController_HttpGetRoutes_MatchEstablishedRouteStyle()
    {
        var routes = HttpGetRoutes(typeof(CveController));

        routes.Keys.Should().BeEquivalentTo(
            "Search", "Count", "CountAll", "GetAll", "CountByKeyword", "SearchByKeyword", "Get", "GetLastPublished", "GetLastModified");
        routes["Search"].Should().BeEquivalentTo("cve/search/{vendor}/{product}/{count}/{page}/{descending}/{byPublished}");
        routes["Count"].Should().BeEquivalentTo("cve/search/{vendor}/{product}/count");
        routes["CountAll"].Should().BeEquivalentTo("cve/all/count");
        routes["GetAll"].Should().BeEquivalentTo("cve/all/{count}/{page}/{descending}/{byPublished}");
        routes["CountByKeyword"].Should().BeEquivalentTo("cve/search-count/{keyword}");
        routes["SearchByKeyword"].Should().BeEquivalentTo("cve/search/{keyword}/{count}/{page}/{descending}/{byPublished}");
        routes["Get"].Should().BeEquivalentTo("cve/{cveId}");
        routes["GetLastPublished"].Should().BeEquivalentTo("cve/last/published/{vendor}/{product}");
        routes["GetLastModified"].Should().BeEquivalentTo("cve/last/modified/{vendor}/{product}");
    }

    [Fact]
    public void CweController_HttpGetRoutes_MatchEstablishedRouteStyle()
    {
        var routes = HttpGetRoutes(typeof(CweController));

        routes.Keys.Should().BeEquivalentTo("CountAll", "ListAll", "CountByKeyword", "SearchByKeyword", "Get");
        routes["CountAll"].Should().BeEquivalentTo("cwe/all/count");
        routes["ListAll"].Should().BeEquivalentTo("cwe/all/{count}/{page}");
        routes["CountByKeyword"].Should().BeEquivalentTo("cwe/search-count/{keyword}");
        routes["SearchByKeyword"].Should().BeEquivalentTo("cwe/search/{keyword}/{count}/{page}");
        routes["Get"].Should().BeEquivalentTo("cwe/{cweId}");
    }

    [Fact]
    public void CapecController_HttpGetRoutes_MatchEstablishedRouteStyle()
    {
        var routes = HttpGetRoutes(typeof(CapecController));

        routes.Keys.Should().BeEquivalentTo("Get");
        routes["Get"].Should().BeEquivalentTo("capec/{capecId}");
    }

    [Fact]
    public void VendorsController_HttpGetRoutes_MatchEstablishedRouteStyle()
    {
        var routes = HttpGetRoutes(typeof(VendorsController));

        routes.Keys.Should().BeEquivalentTo("GetAllVendors", "GetProductsByVendor");
        routes["GetAllVendors"].Should().BeEquivalentTo("vendors/search/{search}", "vendors");
        routes["GetProductsByVendor"].Should().BeEquivalentTo("vendors/{vendor}");
    }

    [Fact]
    public void AllControllers_HttpGetTemplates_AreLowercasePositionalSegments()
    {
        var controllers = new[] { typeof(CveController), typeof(CweController), typeof(CapecController), typeof(VendorsController) };

        foreach (var (method, route) in controllers.SelectMany(HttpGetRoutes).SelectMany(x => x.Value.Select(route => (x.Key, route))))
        {
            // Route parameter names inside braces are case-insensitive in routing, so only
            // the literal segments are checked for the established lowercase style.
            var literalSegments = Regex.Replace(route, @"\{[^}]*\}", string.Empty);
            literalSegments.Should().Be(literalSegments.ToLowerInvariant(),
                "route templates are lowercase in the established style (method {0}, route {1})", method, route);
            route.Should().NotContain("?", "query-string routes are not part of the established style ({0})", route);
            route.Should().NotContain("[", "positional route parameters are used, not route constraints ({0})", route);
        }
    }

    [Fact]
    public void CountEndpoints_AreSeparateRoutesFromListEndpoints_ConventionHolds()
    {
        // Count routes end in /count or use the search-count keyword segment so one true
        // count request serves all page turns of a result set (CODING_STANDARDS section 3).
        var countRoutes = new[] { typeof(CveController), typeof(CweController) }
            .SelectMany(HttpGetRoutes)
            .SelectMany(x => x.Value)
            .Where(route => route.EndsWith("/count", StringComparison.Ordinal) || route.Contains("/search-count/", StringComparison.Ordinal))
            .ToList();

        countRoutes.Should().BeEquivalentTo(new[]
        {
            "cve/search/{vendor}/{product}/count",
            "cve/all/count",
            "cve/search-count/{keyword}",
            "cwe/all/count",
            "cwe/search-count/{keyword}",
        });
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> HttpGetRoutes(Type controller)
    {
        var prefix = controller.GetCustomAttribute<RouteAttribute>()?.Template
            ?? throw new InvalidOperationException($"{controller.Name} is missing a [Route] prefix");

        return controller.GetMethods()
            .SelectMany(m => m.GetCustomAttributes<HttpGetAttribute>()
                .Select(a => (Method: m.Name, Template: Combine(prefix, a.Template))))
            .GroupBy(x => x.Method, x => x.Template, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.ToList(), StringComparer.Ordinal);
    }

    private static string Combine(string prefix, string? template) =>
        string.IsNullOrEmpty(template) ? prefix : $"{prefix}/{template}";
}
