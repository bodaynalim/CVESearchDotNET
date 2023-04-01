namespace Cve.Net.Search.Domain.ViewModels
{
    public class CweViewModel
    {
        public string CweId { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public string Status { get; set; }

        public string Abstraction { get; set; }

        public string[] RelatedCwes { get; set; }
    }
}
