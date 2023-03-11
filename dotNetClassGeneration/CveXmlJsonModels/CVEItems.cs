using Newtonsoft.Json;
using System.Collections.Generic;

namespace CVESearch.CveXmlJsonModels
{
    public class Cve
    {
        [JsonProperty("data_type")]
        public string DataType { get; set; }

        [JsonProperty("data_format")]
        public string DataFormat { get; set; }

        [JsonProperty("data_version")]
        public string DataVersion { get; set; }

        [JsonProperty("CVE_data_meta")]
        public CveDataMeta CveDataMeta { get; set; }

        [JsonProperty("problemtype")]
        public ProblemType Problemtype { get; set; }

        [JsonProperty("references")]
        public References References { get; set; }

        [JsonProperty("description")]
        public Description Description { get; set; }
    }

    public class CveDataMeta
    {
        [JsonProperty("ID")]
        public string Id { get; set; }

        [JsonProperty("ASSIGNER")]
        public string Assigner { get; set; }
    }

    public class ProblemType
    {
        [JsonProperty("problemtype_data")]
        public ICollection<ProblemtypeData> ProblemtypeData { get; set; }
    }

    public class ProblemtypeData
    {
        [JsonProperty("description")]
        public ICollection<DescriptionData> Description { get; set; }
    }


    public class References
    {
        [JsonProperty("reference_data")]
        public ICollection<ReferenceData> ReferenceData { get; set; }
    }


    public class ReferenceData
    {
        [JsonProperty("url")]
        public string Url { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("refsource")]
        public string RefSource { get; set; }

        [JsonProperty("tags")]
        public ICollection<object> Tags { get; set; }
    }


    public class Description
    {
        [JsonProperty("description_data")]
        public ICollection<DescriptionData> DescriptionData { get; set; }
    }


    public class DescriptionData
    {
        [JsonProperty("lang")]
        public string Lang { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }
    }


    public class Configurations
    {
        [JsonProperty("CVE_data_version")]
        public string CveDataVersion { get; set; }

        [JsonProperty("nodes")]
        public ICollection<object> Nodes { get; set; }
    }


    public class CveItem
    {
        [JsonProperty("cve")]
        public Cve Cve { get; set; }

        [JsonProperty("configurations")]
        public Configurations Configurations { get; set; }

        [JsonProperty("impact")]
        public Cve Impact { get; set; }

        [JsonProperty("publishedDate")]
        public string PublishedDate { get; set; }

        [JsonProperty("lastModifiedDate")]
        public string LastModifiedDate { get; set; }
    }


    public class Anonymous
    {
        [JsonProperty("CVE_data_type")]
        public string CveDataType { get; set; }

        [JsonProperty("CVE_data_format")]
        public string CveDataFormat { get; set; }

        [JsonProperty("CVE_data_version")]
        public string CveDataVersion { get; set; }

        [JsonProperty("CVE_data_numberOfCVEs")]
        public string CveDataNumberOfCves { get; set; }

        [JsonProperty("CVE_data_timestamp")]
        public string CveDataTimestamp { get; set; }

        [JsonProperty("CVE_Items")]
        public ICollection<CveItem> CveItems { get; set; }
    }
}