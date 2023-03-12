using CVESearch.CveXmlJsonModels;
using CVESearch.MongoModels;
using MyNamespace;
using System.Linq;

namespace CVESearch.Infrastructure.Extensions
{
    public static class ToMongoModelExtensions
    {
        public static CweMongoModel ToCweMongoModel(this WeaknessType cwe)
        {
            return new CweMongoModel
            {
                Abstraction = cwe.Abstraction,
                CweId = cwe.ID,
                Name = cwe.Name,
                Description = cwe.Description,
                Status = cwe.Status,
                RelatedCwes = cwe.Related_Weaknesses.Select(s => s.CWE_ID).ToArray()
            };
        }

        public static CapecMongoModel ToCapecMongoModel(this AttackPatternType attackPatternType)
        {
            return new CapecMongoModel
            {
                CapecId = attackPatternType.ID,
                ExecutionFlowTypeAttacks = attackPatternType.Execution_Flow.Select(s => new ExecutionFlowTypeAttack
                {
                    DescriptionField = s.Description.Any.FirstOrDefault().Value,
                    Phase = s.Phase.ToString(),
                    Techniques = s.Technique.Select(t => t.Any.FirstOrDefault().Value).ToArray(),
                    Step = s.Step,
                }).ToArray(),
                Summary = attackPatternType.Description.Any.FirstOrDefault().Value,
                LikelyhoodAttack = attackPatternType.Likelihood_Of_Attack.ToString(),
                Name = attackPatternType.Name,
                Prerequisites = attackPatternType.Prerequisites.Select(p => p.Any.FirstOrDefault().Value).ToArray(),
                RelatedCapecs = attackPatternType.Related_Attack_Patterns.Select(a => a.CAPEC_ID).ToArray(),
                RelatedCwes= attackPatternType.Related_Weaknesses.Select(w => w.CWE_ID).ToArray(),
                Severity = attackPatternType.Typical_Severity.ToString(),
                Solutions = attackPatternType.Mitigations.Select(p => p.Any.FirstOrDefault().Value).ToArray(),
                Taxonomy = attackPatternType.Taxonomy_Mappings.Select(t => new Taxonomy
                {
                    EntryId = t.Entry_ID,
                    EntryName = t.Entry_Name,
                    Name = t.Taxonomy_Name.ToString()

                }).ToArray()
            };
        }

        public static CveMongoModel ToCveMongoModel(this Def_cve_item cveItem)
        {
            return new CveMongoModel
            {

            };
        }
    }
}
