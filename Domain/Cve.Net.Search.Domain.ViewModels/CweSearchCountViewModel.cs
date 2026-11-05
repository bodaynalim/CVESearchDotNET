namespace Cve.Net.Search.Domain.ViewModels;

/// <summary>
/// Count of CWE entries in a listing.
/// </summary>
public record CweSearchCountViewModel
{
    public long Total { get; init; }
}
