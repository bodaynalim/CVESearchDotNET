using Cve.Application.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Cve.Net.Search.Web.Infrastructure.Hangfire;

/// <summary>
/// Ensures all Mongo indexes are created (awaited) once at application startup,
/// instead of fire-and-forget index creation in service constructors.
/// </summary>
public class IndexBootstrapper : IHostedService
{
    private readonly IEnumerable<IIndexInitializer> _indexInitializers;
    private readonly ILogger<IndexBootstrapper> _logger;

    public IndexBootstrapper(IEnumerable<IIndexInitializer> indexInitializers, ILogger<IndexBootstrapper> logger)
    {
        _indexInitializers = indexInitializers;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var initializer in _indexInitializers)
        {
            try
            {
                await initializer.EnsureIndexesAsync(cancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to ensure Mongo indexes for {Type}", initializer.GetType().Name);
                throw;
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
