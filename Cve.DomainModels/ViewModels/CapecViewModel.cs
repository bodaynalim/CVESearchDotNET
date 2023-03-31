using Cve.DomainModels.MongoModels.Capec;

namespace Cve.DomainModels.ViewModels
{
    public class CapecViewModel
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
}
