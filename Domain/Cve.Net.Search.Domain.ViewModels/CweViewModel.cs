namespace Cve.Net.Search.Domain.ViewModels;

public record CweViewModel
{
    public string CweId { get; init; }

    public string Name { get; init; }

    public string Description { get; init; }

    public string Status { get; init; }

    public string Abstraction { get; init; }

    public string[] RelatedCwes { get; init; }
}
