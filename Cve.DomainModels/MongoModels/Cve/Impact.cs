namespace Cve.DomainModels.MongoModels.Cve
{
    /// <summary>
    /// CVSS impact
    /// </summary>
    public class Impact
    {
        public string Confidentiality { get; set; }

        public string Integrity { get; set; }

        public string Availability { get; set; }
    }
}
