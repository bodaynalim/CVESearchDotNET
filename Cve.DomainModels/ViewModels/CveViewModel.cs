using Cve.DomainModels.MongoModels.Cve;
using System;

namespace Cve.DomainModels.ViewModels
{
    public class CveViewModel
    {
        /// <summary>
        /// CVE name
        /// </summary>
        public string CveId { get; set; }

        /// <summary>
        /// Assigner
        /// </summary>
        public string Assigner { get; set; }

        /// <summary>
        /// Published date
        /// </summary>
        public DateTime Published { get; set; }

        /// <summary>
        /// Last modified date
        /// </summary>
        public DateTime Modified { get; set; }

        /// <summary>
        /// Related CWEs
        /// </summary>
        public string[] Cwes { get; set; }

        /// <summary>
        /// Summary
        /// </summary>
        public string Summary { get; set; }

        /// <summary>
        /// CVSS2
        /// </summary>
        public CvssTwo Cvss2 { get; set; }

        /// <summary>
        /// CVSS3
        /// </summary>
        public CvssThree Cvss3 { get; set; }

        public string[] ReferencesUrls { get; set; }

        /// <summary>
        /// Cpe 2.3 Uris
        /// </summary>
        public string[] VulnerableConfigurations { get; set; }
    }
}
