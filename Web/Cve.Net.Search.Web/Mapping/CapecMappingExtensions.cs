using Cve.Net.Search.Domain.Database.MongoModels.Capec;
using Cve.Net.Search.Domain.ViewModels;

namespace CVESearch.Mapping;

/// <summary>
/// Explicit mapping from the persisted CAPEC Mongo model to the API wire contract.
/// Every member maps by name; nested types are shared between model and ViewModel.
/// </summary>
public static class CapecMappingExtensions
{
    /// <summary>
    /// Maps a CAPEC entry to its <see cref="CapecViewModel"/> wire representation.
    /// </summary>
    public static CapecViewModel ToCapecViewModel(this CapecMongoModel model) => new()
    {
        Name = model.Name,
        CapecId = model.CapecId,
        Summary = model.Summary,
        Prerequisites = model.Prerequisites,
        Solutions = model.Solutions,
        RelatedCapecs = model.RelatedCapecs,
        RelatedCwes = model.RelatedCwes,
        Severity = model.Severity,
        Taxonomy = model.Taxonomy,
        LikelyhoodAttack = model.LikelyhoodAttack,
        ExecutionFlowTypeAttacks = model.ExecutionFlowTypeAttacks,
    };
}
