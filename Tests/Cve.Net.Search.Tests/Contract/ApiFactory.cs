using Cve.Application.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Web;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NSubstitute;

namespace Cve.Net.Search.Tests;

/// <summary>
/// WebApplicationFactory seam for T04 status-code coverage. Program is public and all
/// controller-facing Mongo services are plain DI singletons, so the composition can be
/// stubbed without any production modification: the four services are replaced with
/// NSubstitute substitutes and ALL hosted services are removed (IndexBootstrapper would
/// create real Mongo indexes and the Hangfire server would execute real import jobs —
/// live HTTP downloads plus database writes are forbidden in tests, see AGENTS.md).
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    public static CveMongoModel? NoCve => null;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            RemoveHostedServices(services);

            // Every Get misses by default (404 scenarios); the 200 scenarios override
            // with their own stub via WithWebHostBuilder.
            var cve = Substitute.For<ICveMongoService>();
            // The controller seam models a cache miss as a null service return
            // (CODING_STANDARDS section 7), which the record's non-nullable signature
            // does not express — hence the justified null-forgiving cast.
            cve.Get(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns((CveMongoModel)null!);
            ReplaceWith(services, cve);
            ReplaceWith(services, Substitute.For<ICweMongoService>());
            ReplaceWith(services, Substitute.For<ICapecMongoService>());
            ReplaceWith(services, Substitute.For<IVendorMongoService>());
        });
    }

    /// <summary>Builds a client whose Cve service returns the given CVE (200 scenario).</summary>
    public HttpClient CreateClientWithCve(CveMongoModel cve) =>
        WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            RemoveHostedServices(s);
            var cveService = Substitute.For<ICveMongoService>();
            cveService.Get(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(cve);
            ReplaceWith(s, cveService);
        })).CreateClient();

    private static void RemoveHostedServices(IServiceCollection services)
    {
        for (var i = services.Count - 1; i >= 0; i--)
        {
            if (services[i].ServiceType == typeof(IHostedService))
                services.RemoveAt(i);
        }
    }

    private static void ReplaceWith<T>(IServiceCollection services, T substitute) where T : class
    {
        var descriptor = services.Single(d => d.ServiceType == typeof(T));
        services.Remove(descriptor);
        services.AddSingleton(substitute);
    }
}
