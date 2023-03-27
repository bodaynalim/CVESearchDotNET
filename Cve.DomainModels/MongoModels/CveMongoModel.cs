using System;

namespace Cve.DomainModels.MongoModels
{
    public class CveMongoModel : BaseMongoModel
    {
        public string CveId { get; set; }

        public string Assigner { get; set; }

        public DateTime Published { get; set; }

        public DateTime Modified { get; set; }

        public ProblemData[] Cwes { get; set; }

        public string Summary { get; set; }

        public CvssTwo Cvss2 { get; set; }

        public CvssThree Cvss3 { get; set; }

        public Reference[] References { get; set; }
        
        public CpeTwoThree[] VulnerableConfigurations { get; set; }

        public VulnarableProducts[] Products { get; set; }
    }

    public class CvssThree
    {
        public AccessThree Access { get; set; }

        public Impact Impact { get; set; }

        public double? BaseScore { get; set; }

        public double? ExploitabilityScore { get; set; }

        public double? ImpactScore { get; set; }

        public string VectorString { get; set; }

        public string BaseSeverity { get; set; }

        public string Version { get; set; }
    }

    public class CvssTwo
    {
        public AccessTwo Access { get; set; }

        public Impact Impact { get; set; }

        public double? BaseScore { get; set; }

        public double? ExploitabilityScore { get; set; }

        public double? ImpactScore { get; set; }

        public string VectorString { get; set; }

        public string Severity { get; set; }

        public string Version { get; set; }
    }

    public class AccessTwo
    {
        public string Vector { get; set; }
        
        public string Complexity { get; set; }
        
        public string Authentication { get; set; }
    }

    public class AccessThree
    {
        public string Vector { get; set; }

        public string Complexity { get; set; }

        public string PrivilegesRequired { get; set; }

        public string UserInteraction { get; set; }

        public string Scope { get; set; }
    }

    public class Impact
    {
        public string Confidentiality { get; set; }

        public string Integrity { get; set; }

        public string Availability { get; set; }
    }

    public class Reference
    {
        public string Url { get; set; }
       
        public string Name { get; set; }
        
        public string Refsource { get; set; }

        public string[] Tags { get; set; }
    }

    public class ProblemData
    {
        public string[] Cwes { get; set; }
    }

    public class CpeTwoThree
    {        
        public string VersionStartExcluding { get; set; }
        
        public string VersionStartIncluding { get; set; }
        
        public string VersionEndExcluding { get; set; }
        
        public string VersionEndIncluding { get; set; }

        public bool Vulnerable { get; set; }

        public string CpeUri { get; set; }
    }

    public class VulnarableProducts
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
}
