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

        public string[] References { get; set; }
        
        public string[] VulnerableConfigurations { get; set; }

        public string[] VulnerableProducts { get; set; }

        public string[] VulnerableConfigurationsTrimmed { get; set; }

        public string[] VulnerableProductsTrimmed { get; set; }

        public string[] Products { get; set; }

        public string[] Vendors { get; set; }

        public string[] VulnerableConfigurationCpeTwoTwo { get; set; }
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
