namespace Cve.DomainModels.Configuration
{
    public class VulnerabilitiesUrls
    {
        public string CveRecentUrl { get; set; }
        public string CveModifiedUrl { get; set; }
        public string CweUrl { get; set; }
        public string CapecUrl { get; set; }
        public string CveRecentJsonName { get; set; }
        public string CveModifiedJsonName { get; set; }
        public int StartTracking { get; set; }
        public string CveJsonNameTemplate { get; set; }
        public string CveJsonNameUrlTemplate { get; set; }
    }
}
