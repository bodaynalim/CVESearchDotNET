using Cve.Net.Search.Web.Infrastructure.Hangfire;
using FluentAssertions;
using Hangfire.MemoryStorage;
using Xunit;

namespace Cve.Net.Search.Tests;

public class HangfireStorageOptionsFactoryTests
{
    [Fact]
    public void MemoryStorageOptions_HaveFetchNextJobTimeout_GreaterThanDefaultThirtyMinutes()
    {
        var options = HangfireStorageOptionsFactory.CreateMemoryStorageOptions();

        options.Should().NotBeNull();

        var defaultOptions = new MemoryStorageOptions();

        // Regression for the bug: with the default 30-minute FetchNextJobTimeout Hangfire
        // re-fetches the long-running initial import job and aborts it after 30 minutes.
        options.FetchNextJobTimeout.Should().BeGreaterThan(defaultOptions.FetchNextJobTimeout);
        options.FetchNextJobTimeout.Should().BeGreaterThanOrEqualTo(TimeSpan.FromHours(5));

        // Expiration checks stay at library defaults.
        options.JobExpirationCheckInterval.Should().Be(new MemoryStorageOptions().JobExpirationCheckInterval);
    }
}
