using Hangfire.Mongo;
using Hangfire.Mongo.Migration.Strategies;
using Hangfire.Mongo.Migration.Strategies.Backup;

namespace Cve.Net.Search.Web.Infrastructure.Hangfire;

/// <summary>
/// Central place where Hangfire storage options are configured.
/// </summary>
public static class HangfireStorageOptionsFactory
{
    /// <summary>
    /// Hangfire collections are namespaced inside the shared application database
    /// so they can coexist with the vulnerability data collections.
    /// </summary>
    public const string CollectionPrefix = "hangfire";

    /// <summary>
    /// Longest planned background-job duration: the initial database population.
    /// The invisibility timeout must be greater than the longest run, otherwise
    /// Hangfire.Mongo considers the fetched job abandoned and Hangfire aborts the
    /// running invocation with JobAbortedException (the MemoryStorage equivalent
    /// was FetchNextJobTimeout, see ADR 0004 for the retry model this protects).
    /// </summary>
    private static readonly TimeSpan SlidingInvisibilityTimeout = TimeSpan.FromHours(6);

    /// <summary>
    /// Builds the Mongo storage options: collection prefix, long invisibility
    /// timeout and automatic schema migration.
    /// </summary>
    public static MongoStorageOptions CreateMongoStorageOptions()
    {
        return new MongoStorageOptions
        {
            Prefix = CollectionPrefix,
            SlidingInvisibilityTimeout = SlidingInvisibilityTimeout,
            MigrationOptions = new MongoMigrationOptions
            {
                // Keep automatic: without it a package upgrade changes the schema version
                // and the storage fails to start until migration is run manually.
                MigrationStrategy = new MigrateMongoMigrationStrategy(),
                BackupStrategy = new NoneMongoBackupStrategy()
            }
        };
    }
}
