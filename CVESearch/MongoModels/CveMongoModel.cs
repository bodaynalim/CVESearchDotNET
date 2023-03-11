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

        public double? Cvss { get; set; }

        public DateTime CvssTime { get; set; }

        public Access Access { get; set; }

        public Impact Impact { get; set; }

        public double? Cvss3 { get; set; }

        public double? ExploitabilityScore { get; set; }

        public double? ImpactScore { get; set; }

        public string CvssVector { get; set; }

        public ICollection<string> References { get; set; }
        
        public ICollection<string> VulnerableConfigurations { get; set; }

        public ICollection<string> VulnerableProducts { get; set; }

        public ICollection<string> Products { get; set; }

        public ICollection<string> Vendors { get; set; }
    }

    public class Access
    {
        public AccessVectorType Vector { get; set; }
        
        public AccessComplexityType Complexity { get; set; }
        
        public AuthenticationType Authentication { get; set; }
    }

    public class Impact
    {
        public CiaType Confidentiality { get; set; }

        public CiaType Integrity { get; set; }

        public CiaType Availability { get; set; }
    }
}
