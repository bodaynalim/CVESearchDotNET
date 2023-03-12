using CVESearch.CveXmlJsonModels;
using System;
using System.Collections.Generic;

namespace CVESearch.MongoModels
{
    public class CveMongoModel : BaseMongoModel
    {
        public string CveId { get; set; }

        public string Assigner { get; set; }

        public DateTime Published { get; set; }

        public DateTime Modified { get; set; }

        public string Cwe { get; set; }

        public string Summary { get; set; }

        public CvssTwo Cvss2 { get; set; }

        public CvssThree Cvss3 { get; set; }

        public string[] References { get; set; }
        
        public string[] VulnerableConfigurations { get; set; }

        public string[] VulnerableProducts { get; set; }

        public string[] VulnerableConfigurationsTrimmed { get; set; }

        public string[] VulnerableProductsTrimmed { get; set; }

        public string[] Products { get; set; }

        public string[] Vendors { get; set; }

        public string[] VulnerableConfigurationCpeTwoTwo { get; set; }
    }

    public class CvssThree
    {
        public Access Access { get; set; }

        public Impact Impact { get; set; }

        public double? BaseScore { get; set; }

        public double? ExploitabilityScore { get; set; }

        public double? ImpactScore { get; set; }

        public string VectorString { get; set; }

        public string BaseSeverity { get; set; }
    }

    public class CvssTwo
    {
        public Access Access { get; set; }

        public Impact Impact { get; set; }

        public double? BaseScore { get; set; }

        public double? ExploitabilityScore { get; set; }

        public double? ImpactScore { get; set; }

        public string VectorString { get; set; }

        public string Severity { get; set; }
    }

    public class Access
    {
        public string Vector { get; set; }
        
        public string Complexity { get; set; }
        
        public string Authentication { get; set; }
    }

    public class Impact
    {
        public string Confidentiality { get; set; }

        public string Integrity { get; set; }

        public string Availability { get; set; }
    }
}
