namespace Cve.Net.Search.Domain.Common.Cve
{
    /// <summary>
    /// Common Vulnerability Scoring System v3 (CVSS3)
    /// </summary>
    public class CvssThree
    {
        /// <summary>
        /// Exploitability metrics
        /// </summary>
        public AttackThree Attack { get; set; }

        /// <summary>
        /// Impact
        /// </summary>
        public Impact Impact { get; set; }

        /// <summary>
        /// CVSS 3.0 base score
        /// </summary>
        public double? BaseScore { get; set; }

        /// <summary>
        /// Exploitability score
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
        /// Base severity
        /// </summary>
        public string BaseSeverity { get; set; }

        /// <summary>
        /// Version
        /// </summary>
        public string Version { get; set; }

        public override string ToString()
        {
            return $"CVSS 3.0: \n" +
                $"Attack: {Attack} \n" +
                $"Impact: {Impact} \n" +
                $"Impact score: {ImpactScore} \n" +
                $"Base score: {BaseScore} \n" +
                $"Exploitability score: {ExploitabilityScore} \n" +
                $"Vector string: {VectorString} \n" +
                $"Base severity: {BaseSeverity} \n" +
                $"Version: {Version}";
        }
    }

    /// <summary>
    /// The Exploitability metrics reflect the ease and technical means by which the vulnerability can be exploited.
    /// </summary>
    public class AttackThree
    {
        /// <summary>
        /// This metric reflects the context by which vulnerability exploitation is possible
        /// </summary>
        public string Vector { get; set; }

        /// <summary>
        /// This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability
        /// </summary>
        public string Complexity { get; set; }

        /// <summary>
        /// This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability
        /// </summary>
        public string PrivilegesRequired { get; set; }

        /// <summary>
        /// This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component
        /// </summary>
        public string UserInteraction { get; set; }

        /// <summary>
        /// An important property captured by CVSS v3.0 is the ability for a vulnerability in one software component to impact resources beyond its means, or privileges
        /// </summary>
        public string Scope { get; set; }

        public override string ToString()
        {
            return $"Vector: {Vector}, Complexity: {Complexity}, Scope: {Scope},\n" +
                $"Privileges required: {PrivilegesRequired}, User interaction: {UserInteraction}";
        }
    }
}
