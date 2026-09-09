namespace Cve.Net.Search.Domain.Database.MongoModels.Cve;

/// <summary>
/// Vulnerable vendor with products
/// </summary>
public class VulnerableProducts
{
    public string Vendor { get; set; }

    public SoftwareWithVersions[] Softwares { get; set; }
}

public class SoftwareWithVersions
{
    public string SoftwareName { get; set; }

    public VersionOs[] Versions { get; set; }
}

public class VersionOs
{
    public string Version { get; set; }

    public string Os { get; set; }

    public string Bitness { get; set; }
}
