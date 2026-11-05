using Cve.Application.Helpers;
using Cve.Application.Services;
using Cve.Net.Search.Domain.Database.MongoModels;
using MongoDB.Driver;

namespace Cve.Infrastructure.Services.InitialImport;

public class InitialImportStateService : IInitialImportStateService, IIndexInitializer
{
    public const string StepCwes = "cwes";
    public const string StepCapecs = "capecs";
    public const string StepCvesPrefix = "cves-";

    private IMongoCollection<InitialImportStateMongoModel> Collection { get; }

    public InitialImportStateService(IMongoDatabase db)
    {
        Collection = db.GetCollection<InitialImportStateMongoModel>("ImportState");
    }

    public Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        return Collection.Indexes.CreateOneAsync(
            new CreateIndexModel<InitialImportStateMongoModel>(
                Builders<InitialImportStateMongoModel>.IndexKeys.Ascending(s => s.Step),
                new CreateIndexOptions { Unique = true }),
            cancellationToken: cancellationToken);
    }

    public async Task<bool> IsStepCompletedAsync(string step, CancellationToken cancellationToken = default)
    {
        // Existence query instead of CountDocumentsAsync: cheaper for a yes/no check.
        var any = await Collection
            .Find(Builders<InitialImportStateMongoModel>.Filter.Eq(s => s.Step, step))
            .Limit(1)
            .AnyAsync(cancellationToken);

        return any;
    }

    public async Task MarkStepCompletedAsync(string step, CancellationToken cancellationToken = default)
    {
        try
        {
            await Collection.UpdateOneAsync(
                Builders<InitialImportStateMongoModel>.Filter.Eq(s => s.Step, step),
                Builders<InitialImportStateMongoModel>.Update
                    .Set(s => s.CompletedAt, DateTime.UtcNow)
                    .SetOnInsert(s => s.Step, step),
                new UpdateOptions { IsUpsert = true },
                cancellationToken);
        }
        catch (MongoWriteException e) when (e.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            // Another application instance marked the same step concurrently: fine.
        }
    }
}
