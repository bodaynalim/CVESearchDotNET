using System.Threading.Tasks;
using System.Threading;

namespace Cve.Application.Services;

/// <summary>
/// Implemented by Mongo services that define indexes for their collection.
/// Index creation is awaited once at application startup (see IndexBootstrapper)
/// instead of running fire-and-forget in service constructors.
/// </summary>
public interface IIndexInitializer
{
    /// <summary>
    /// Creates (if not existing) the indexes required by the service collection.
    /// </summary>
    Task EnsureIndexesAsync(CancellationToken cancellationToken = default);
}
