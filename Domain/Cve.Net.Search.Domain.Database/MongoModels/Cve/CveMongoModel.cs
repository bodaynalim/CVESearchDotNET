using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Extensions;
using System;
using System.ComponentModel;
using System.Linq;

namespace Cve.Net.Search.Domain.Database.MongoModels.Cve
{
    /// <summary>
    /// CVE mongo model
    /// </summary>
    public class CveMongoModel : BaseMongoModel
    {
        public string CveId { get; set; }

        [Description("Assigner")]
        public string Assigner { get; set; }

        [Description("Published date")]
        public DateTime Published { get; set; }

        [Description("Last Modified")]
        public DateTime Modified { get; set; }

        [Description("Common Weakness Enumerations")]
        public ProblemData[] Cwes { get; set; }

        public string Summary { get; set; }

        [Description("Common Vulnerability Scoring System v2 (CVSS2)")]
        public CvssTwo Cvss2 { get; set; }

        [Description("Common Vulnerability Scoring System v3 (CVSS3)")]
        public CvssThree Cvss3 { get; set; }

        [Description("Common Vulnerability Scoring System v3.1 (CVSS3.1)")]
        public CvssThree Cvss31 { get; set; }

        [Description("References")]
        public Reference[] References { get; set; }

        [Description("Common Platform Enumerations")]
        public CpeTwoThree[] VulnerableConfigurations { get; set; }

        public VulnarableProducts[] Products { get; set; }        
    }

    public class Reference
    {
        public string Url { get; set; }

        public string Name { get; set; }

        public string Refsource { get; set; }

        public string[] Tags { get; set; }

        public override string ToString()
        {
            return $"Reference: {Url} [{Tags.JoinToString(", ")}]";
        }
    }

    public class ProblemData
    {
        public string[] Cwes { get; set; }

        public override string ToString()
        {
            return Cwes?.Any() == true 
                ? Cwes.JoinToString(", ")
                : string.Empty;
        }
    }
}
