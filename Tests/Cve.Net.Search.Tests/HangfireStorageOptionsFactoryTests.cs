using Cve.Net.Search.Web.Infrastructure.Hangfire;
using FluentAssertions;
using Hangfire.Mongo;
using Hangfire.Mongo.Migration.Strategies;
using Hangfire.Mongo.Migration.Strategies.Backup;
using Xunit;

namespace Cve.Net.Search.Tests;

public class HangfireStorageOptionsFactoryTests
{
    [Fact]
    public void MongoStorageOptions_HaveLongInvisibilityTimeout_AndAutomaticMigration()
    {
        var options = HangfireStorageOptionsFactory.CreateMongoStorageOptions();

        options.Should().NotBeNull();

        // Collections are namespaced inside the shared application database.
        options.Prefix.Should().Be(HangfireStorageOptionsFactory.CollectionPrefix);

        // Regression for the bug: with a short invisibility timeout Hangfire
        // re-fetches the long-running initial import job and aborts it after
        // 30 minutes (MemoryStorage equivalent: FetchNextJobTimeout).
        options.SlidingInvisibilityTimeout.Should().BeGreaterThanOrEqualTo(TimeSpan.FromHours(5));

        // Regression for the bug: with the default WatchCollection strategy on a
        // standalone MongoDB (no replica set) MongoJobQueueWatcher crashes with
        // "The $changeStream stage is only supported on replica sets or mongos".
        options.CheckQueuedJobsStrategy.Should().Be(CheckQueuedJobsStrategy.TailNotificationsCollection);
    }
}
