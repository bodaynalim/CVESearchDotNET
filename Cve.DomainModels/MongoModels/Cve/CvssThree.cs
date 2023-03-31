using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cve.DomainModels.MongoModels.Cve
{
    /// <summary>
    /// Common Vulnerability Scoring System v3 (CVSS3)
    /// </summary>
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

    public class AccessThree
    {
        public string Vector { get; set; }

        public string Complexity { get; set; }

        public string PrivilegesRequired { get; set; }

        public string UserInteraction { get; set; }

        public string Scope { get; set; }
    }
}
