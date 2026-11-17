using Cve.Net.Search.Domain.Database.CveXmlJsonModels;
using Cve.Net.Search.Domain.Database.MongoModels.Cwe;
using Cve.Net.Search.Domain.ViewModels;

namespace CVESearch.Mapping;

/// <summary>
/// Explicit mapping from the persisted CWE Mongo model to the API wire contract.
/// </summary>
public static class CweMappingExtensions
{
    /// <summary>
    /// Maps a CWE entry to its <see cref="CweViewModel"/> wire representation.
    /// </summary>
    public static CweViewModel ToCweViewModel(this CweMongoModel model) => new()
    {
        CweId = model.CweId,
        Name = model.Name,
        Description = model.Description,
        // Non-trivial rule: the two enumerations reach the wire contract as their enum
        // member names via ToString() (not the numeric value).
        Status = model.Status.ToString(),
        Abstraction = model.Abstraction.ToString(),
        RelatedCwes = model.RelatedCwes,
    };
}
