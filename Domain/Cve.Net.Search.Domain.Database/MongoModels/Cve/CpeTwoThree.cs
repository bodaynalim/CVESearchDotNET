namespace Cve.Net.Search.Domain.Database.MongoModels.Cve
{
    /// <summary>
    /// Cpe 2.3
    /// </summary>
    public class CpeTwoThree
    {
        public string VersionStartExcluding { get; set; }

        public string VersionStartIncluding { get; set; }

        public string VersionEndExcluding { get; set; }

        public string VersionEndIncluding { get; set; }

        public bool Vulnerable { get; set; }

        public string CpeUri { get; set; }
    }
}
