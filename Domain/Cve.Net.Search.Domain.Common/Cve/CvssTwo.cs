namespace Cve.Net.Search.Domain.Common.Cve
{
    /// <summary>
    /// Common Vulnerability Scoring System v2 (CVSS2)
    /// </summary>
    public class CvssTwo
    {
        /// <summary>
        /// Access metrics
        /// </summary>
        public AccessTwo Access { get; set; }

        /// <summary>
        /// Potential impact
        /// </summary>
        public Impact Impact { get; set; }

        /// <summary>
        /// Base score
        /// </summary>
        public double? BaseScore { get; set; }

        /// <summary>
        /// This metric measures the current state of exploit techniques or code availability
        /// </summary>
        public double? ExploitabilityScore { get; set; }

        /// <summary>
        /// Impact score
        /// </summary>
        public double? ImpactScore { get; set; }

        /// <summary>
        /// Vector string
        /// </summary>
        public string VectorString { get; set; }

        /// <summary>
        /// Severity
        /// </summary>
        public string Severity { get; set; }

        /// <summary>
        /// Version
        /// </summary>
        public string Version { get; set; }

        public override string ToString()
        {
            return $"CVSS 2.0: \n" +
                $"Access: {Access} \n" +
                $"Impact: {Impact} \n" +
                $"Impact score: {ImpactScore} \n" +
                $"Base score: {BaseScore} \n" +
                $"Exploitability score: {ExploitabilityScore} \n" +
                $"Vector string: {VectorString} \n" +
                $"Severity: {Severity} \n" +
                $"Version: {Version}";
        }
    }

    /// <summary>
    /// The base metric group captures the characteristics of a vulnerability that are constant with time and across user environments
    /// </summary>
    public class AccessTwo
    {
        /// <summary>
        /// This metric reflects how the vulnerability is exploited
        /// </summary>
        public string Vector { get; set; }

        /// <summary>
        /// This metric measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system
        /// </summary>
        public string Complexity { get; set; }

        /// <summary>
        /// This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability
        /// </summary>
        public string Authentication { get; set; }

        public override string ToString()
        {
            return $"Vector: {Vector}, Complexity: {Complexity}, Authentication: {Authentication}";
        }
    }
}
