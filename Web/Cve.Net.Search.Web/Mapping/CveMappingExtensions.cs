using System;
using System.Linq;
using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Domain.ViewModels;

namespace CVESearch.Mapping;

/// <summary>
/// Explicit mappings from the persisted CVE Mongo model to the API wire contract.
/// The mapping rules are the authoritative record for the CVE endpoints' response shape.
/// </summary>
public static class CveMappingExtensions
{
    /// <summary>
    /// Maps a CVE entry to its <see cref="CveViewModel"/> wire representation.
    /// </summary>
    public static CveViewModel ToCveViewModel(this CveMongoModel model) => new()
    {
        CveId = model.CveId,
        Assigner = model.Assigner,
        Published = model.Published,
        Modified = model.Modified,
        // Non-trivial rule: the ProblemData wrappers are flattened away — every CWE id of
        // every weakness entry is collected into one flat string array. A weakness without
        // description data contributes nothing (cf. ToMongoModelExtensions, which can emit
        // a null Cwes array for a weakness lacking descriptions).
        Cwes = model.Cwes?.SelectMany(r => r.Cwes ?? Array.Empty<string>()).ToArray(),
        Summary = model.Summary,
        Cvss2 = model.Cvss2,
        // Non-trivial rule: CVSS 3.0 is used when it carries a BaseScore; otherwise
        // (missing metric, or present but unscored) the CVSS 3.1 metric is used instead.
        Cvss3 = SelectCvss3(model),
        // Non-trivial rule: ReferencesUrls is a pure projection of Reference.Url in payload
        // order; Name/Refsource/Tags are dropped.
        ReferencesUrls = model.References?.Select(r => r.Url).ToArray(),
        // Non-trivial rule: only the CPE URI string is projected from VulnerableConfigurations;
        // version-range properties are dropped.
        VulnerableConfigurations = model.VulnerableConfigurations?.Select(r => r.CpeUri).ToArray(),
    };

    private static CvssThree SelectCvss3(CveMongoModel model) =>
        model.Cvss3 != null && model.Cvss3.BaseScore != null ? model.Cvss3 : model.Cvss31;
}
