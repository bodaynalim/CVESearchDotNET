namespace Cve.Net.Search.Domain.Common.Cve
{
    /// <summary>
    /// The Impact metrics refer to the properties of the impacted component
    /// </summary>
    public class Impact
    {
        /// <summary>
        /// This metric measures the impact on confidentiality of a successfully exploited vulnerability
        /// </summary>
        public string Confidentiality { get; set; }

        /// <summary>
        /// This metric measures the impact to integrity of a successfully exploited vulnerability
        /// </summary>
        public string Integrity { get; set; }

        /// <summary>
        /// This metric measures the impact to availability of a successfully exploited vulnerability
        /// </summary>
        public string Availability { get; set; }

        public override string ToString()
        {
            return $"Confidentiality: {Confidentiality}, Integrity: {Integrity}, Availability: {Availability}";
        }
    }
}
