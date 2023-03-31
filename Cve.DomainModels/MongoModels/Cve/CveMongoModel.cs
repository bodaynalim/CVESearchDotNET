using System;

namespace Cve.DomainModels.MongoModels.Cve
{
    /// <summary>
    /// CVE mongo model
    /// </summary>
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
}
