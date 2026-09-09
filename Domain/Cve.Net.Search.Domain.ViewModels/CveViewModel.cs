using Cve.Net.Search.Domain.Common.Cve;
using System;

namespace Cve.Net.Search.Domain.ViewModels;

public record CveViewModel
{
    /// <summary>
    /// CVE name
    /// </summary>
    public string CveId { get; init; }

    /// <summary>
    /// Assigner
    /// </summary>
    public string Assigner { get; init; }

    /// <summary>
    /// Published date
    /// </summary>
    public DateTime Published { get; init; }

    /// <summary>
    /// Last modified date
    /// </summary>
    public DateTime Modified { get; init; }

    /// <summary>
    /// Related CWEs
    /// </summary>
    public string[] Cwes { get; init; }

    /// <summary>
    /// Summary
    /// </summary>
    public string Summary { get; init; }

    /// <summary>
    /// CVSS2
    /// </summary>
    public CvssTwo Cvss2 { get; init; }

    /// <summary>
    /// CVSS3
    /// </summary>
    public CvssThree Cvss3 { get; init; }

    public string[] ReferencesUrls { get; init; }

    /// <summary>
    /// Cpe 2.3 Uris
    /// </summary>
    public string[] VulnerableConfigurations { get; init; }
}
