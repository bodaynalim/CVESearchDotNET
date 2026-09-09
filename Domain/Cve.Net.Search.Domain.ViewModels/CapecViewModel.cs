using Cve.Net.Search.Domain.Common.Capec;

namespace Cve.Net.Search.Domain.ViewModels;

/// <summary>
/// CAPEC model
/// </summary>
public record CapecViewModel
{
    public string Name { get; init; }

    public string CapecId { get; init; }

    public string Summary { get; init; }

    public string[] Prerequisites { get; init; }

    public string[] Solutions { get; init; }

    public string[] RelatedCapecs { get; init; }

    public string[] RelatedCwes { get; init; }

    public string Severity { get; init; }

    public Taxonomy[] Taxonomy { get; init; }

    public string LikelyhoodAttack { get; init; }

    public ExecutionFlowTypeAttack[] ExecutionFlowTypeAttacks { get; init; }
}
