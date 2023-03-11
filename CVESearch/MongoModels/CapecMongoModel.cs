using CVESearch.CveXmlJsonModels;

namespace CVESearch.MongoModels
{
    public class CapecMongoModel : BaseMongoModel
    {
        public string Name { get; set; }

        public string CapecId { get; set; }

        public string Summary { get; set; }

        public string[] Prerequisites { get; set; }

        public string[] Solutions { get; set; }

        public string[] RelatedCapecs { get; set; }

        public string[] RelatedCwes { get; set; }

        public string Severity { get; set; }

        public Taxonomy[] Taxonomy { get; set; }

        public string LikelyhoodAttack { get; set; }

        public ExecutionFlowTypeAttack[] ExecutionFlowTypeAttacks { get; set; }
    }

    public class Taxonomy
    {
        public string Name { get; set; }

        public string EntryId { get; set; }

        public string EntryName { get; set; }

        public string Url { get; set; }
    }

    public class ExecutionFlowTypeAttack
    {
        public string Step { get; set; }

        public string Phase { get; set; }

        public string DescriptionField { get; set; } 

        public string[] Techniques;
    }
}
