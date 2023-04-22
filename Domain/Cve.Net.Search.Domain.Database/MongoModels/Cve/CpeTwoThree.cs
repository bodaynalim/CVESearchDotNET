namespace Cve.Net.Search.Domain.Database.MongoModels.Cve
{
    /// <summary>
    /// Cpe 2.3
    /// </summary>
    public class CpeTwoThree
    {
        /// <summary>
        /// Version start excluding
        /// </summary>
        public string VersionStartExcluding { get; set; }

        /// <summary>
        /// Version start including
        /// </summary>
        public string VersionStartIncluding { get; set; }

        /// <summary>
        /// Version end excluding
        /// </summary>
        public string VersionEndExcluding { get; set; }

        /// <summary>
        /// Version end including
        /// </summary>
        public string VersionEndIncluding { get; set; }

        /// <summary>
        /// Vulnarable
        /// </summary>
        public bool Vulnerable { get; set; }

        /// <summary>
        /// Cpe Uri
        /// </summary>
        public string CpeUri { get; set; }

        public override string ToString()
        {
            return $"Cpe 2.3:\n " +
                $"Version start excluding: {VersionStartExcluding}\n " +
                $"Version start including: {VersionStartIncluding}\n " +
                $"Version end excluding: {VersionEndExcluding}\n " +
                $"Version end including: {VersionEndIncluding}\n " +
                $"Vulnarable: {Vulnerable}\n " +
                $"Cpe Uri: {CpeUri}";
        }
    }
}
