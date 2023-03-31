namespace Cve.DomainModels.MongoModels.Cve
{
    /// <summary>
    /// Common Vulnerability Scoring System v2 (CVSS2)
    /// </summary>
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
}
