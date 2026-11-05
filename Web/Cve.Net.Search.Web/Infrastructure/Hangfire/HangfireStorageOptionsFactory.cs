using Hangfire.MemoryStorage;

namespace Cve.Net.Search.Web.Infrastructure.Hangfire;

/// <summary>
/// Central place where Hangfire storage options are configured.
/// </summary>
public static class HangfireStorageOptionsFactory
{
    /// <summary>
    /// Longest planned background-job duration: the initial database population.
    /// The fetch timeout must be greater than the longest run, otherwise Hangfire
    /// re-fetches the job and aborts the running invocation with JobAbortedException.
    /// </summary>
    private static readonly TimeSpan FetchNextJobTimeout = TimeSpan.FromHours(6);

    public static MemoryStorageOptions CreateMemoryStorageOptions()
    {
        return new MemoryStorageOptions
        {
            FetchNextJobTimeout = FetchNextJobTimeout
        };
    }
}
