using Cve.Net.Search.Domain.Common.Capec;
using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels.NVDApi.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Capec;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cwe;
using System;
using System.Linq;
using Reference = Cve.Net.Search.Domain.Database.MongoModels.Cve.Reference;

namespace Cve.Infrastructure.Extensions
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
                RelatedCwes = cwe.Related_Weaknesses?.Select(s => s.CWE_ID).ToArray()
            };
        }

        public static CapecMongoModel ToCapecMongoModel(this AttackPatternType attackPatternType)
        {
            return new CapecMongoModel
            {
                CapecId = attackPatternType.ID,
                ExecutionFlowTypeAttacks = attackPatternType.Execution_Flow?.Select(s => new ExecutionFlowTypeAttack
                {
                    DescriptionField = s.Description?.Any?.FirstOrDefault()?.Value,
                    Phase = s.Phase.ToString(),
                    Techniques = s.Technique?.Select(t => t.Any?.FirstOrDefault()?.Value).Where(v => v != null).ToArray(),
                    Step = s.Step,
                }).ToArray(),
                Summary = attackPatternType.Description?.Any?.FirstOrDefault()?.Value,
                LikelyhoodAttack = attackPatternType.Likelihood_Of_Attack.ToString(),
                Name = attackPatternType.Name,
                Prerequisites = attackPatternType.Prerequisites?.Select(p => p.Any?.FirstOrDefault()?.Value).Where(v => v != null).ToArray(),
                RelatedCapecs = attackPatternType.Related_Attack_Patterns?.Select(a => a.CAPEC_ID).ToArray(),
                RelatedCwes = attackPatternType.Related_Weaknesses?.Select(w => w.CWE_ID).ToArray(),
                Severity = attackPatternType.Typical_Severity.ToString(),
                Solutions = attackPatternType.Mitigations?.Select(p => p.Any.FirstOrDefault()?.Value).Where(v => v != null).ToArray(),
                Taxonomy = attackPatternType.Taxonomy_Mappings?.Select(t => new Taxonomy
                {
                    EntryId = t.Entry_ID,
                    EntryName = t.Entry_Name,
                    Name = t.Taxonomy_Name.ToString()
                }).ToArray()
            };
        }

        public static (CveMongoModel, VulnarableProducts[]) ToCveMongoModel(this CveItemModel cveItem)
        {
            Func<Def_cpe_match, CpeTwoThree> cpeMongo = (s) => new CpeTwoThree
            {
                CpeUri = s.Cpe23Uri,
                VersionEndExcluding = s.VersionEndExcluding,
                VersionEndIncluding = s.VersionEndIncluding,
                VersionStartExcluding = s.VersionStartExcluding,
                VersionStartIncluding = s.VersionStartIncluding,
                Vulnerable = s.Vulnerable
            };

            var cpesTwoThree = cveItem.Configurations.Nodes.SelectMany(s => s.Cpe_match)
                                .Where(c => c.Vulnerable)
                                .Select(cpeMongo)
                                .ToArray();

            if (cveItem.Configurations.Nodes.Any(s => s.Children?.Any() == true))
            {
                var cpeChildren = cveItem.Configurations.Nodes.SelectMany(s => s.Children)
                     .SelectMany(s => s.Cpe_match)
                     .Where(c => c.Vulnerable && cpesTwoThree.All(s => s.CpeUri != c.Cpe23Uri))
                     .Select(cpeMongo)
                     .ToArray();

                if (cpeChildren.Any())
                    cpesTwoThree = cpesTwoThree.Concat(cpeChildren).ToArray();
            }

            var vendorsAndProducts = cpesTwoThree.Select(s => s.CpeUri.Split(':', StringSplitOptions.RemoveEmptyEntries))
                .Select(v => new { Vendor = v[3], Software = v[4], Version = v[5], Os = v[10], Bitness = v[11] })
                .GroupBy(v => v.Vendor).Select(v => new VulnarableProducts 
                { 
                    Vendor = v.Key,
                    Softwares = v.GroupBy(s => s.Software).Select(g => new SoftwareWithVersions
                    {
                        SoftwareName = g.Key,
                        Versions = g.Select(v => new VersionOs { Version = v.Version, Os = v.Os, Bitness = v.Bitness })
                                    .DistinctBy(s => $"{s.Version} {s.Os} {s.Bitness}")
                                    .ToArray()
                    }).ToArray()
                }).ToArray();

            return (new CveMongoModel
            {
                Published = DateTime.Parse(cveItem.PublishedDate).ToUniversalTime(),
                Modified = DateTime.Parse(cveItem.LastModifiedDate).ToUniversalTime(),
                CveId = cveItem.Cve.CVE_data_meta.ID,
                Assigner = cveItem.Cve.CVE_data_meta.ASSIGNER,
                Cwes = cveItem.Cve.Problemtype.Problemtype_data.Select(p => new ProblemData
                {
                    Cwes = p.Description.Select(d => d.Value).ToArray()
                }).ToArray(),
                Cvss2 = new CvssTwo
                {
                    Access = new AccessTwo
                    {
                        Authentication = cveItem.Impact?.BaseMetricV2?.CvssV2.Authentication.ToString(),
                        Complexity = cveItem.Impact?.BaseMetricV2?.CvssV2.AccessComplexity.ToString(),
                        Vector = cveItem.Impact?.BaseMetricV2?.CvssV2.AccessVector.ToString()
                    },
                    VectorString = cveItem.Impact?.BaseMetricV2?.CvssV2.VectorString,
                    BaseScore = cveItem.Impact?.BaseMetricV2?.CvssV2.BaseScore,
                    ExploitabilityScore = cveItem.Impact?.BaseMetricV2?.ExploitabilityScore,
                    Severity = cveItem.Impact?.BaseMetricV2?.Severity,
                    ImpactScore = cveItem.Impact?.BaseMetricV2?.ImpactScore,
                    Impact = new Impact
                    {
                        Availability = cveItem.Impact?.BaseMetricV2?.CvssV2.AvailabilityImpact.ToString(),
                        Confidentiality = cveItem.Impact?.BaseMetricV2?.CvssV2.ConfidentialityImpact.ToString(),
                        Integrity = cveItem.Impact?.BaseMetricV2?.CvssV2.IntegrityImpact.ToString()
                    },
                    Version = cveItem.Impact?.BaseMetricV2?.CvssV2.Version.ToString()
                },
                Cvss3 = new CvssThree
                {
                    Attack = new AttackThree
                    {                        
                        Complexity = cveItem.Impact?.BaseMetricV3?.CvssV3.AttackComplexity.ToString(),
                        Vector = cveItem.Impact?.BaseMetricV3?.CvssV3.AttackVector.ToString(),
                        PrivilegesRequired = cveItem.Impact?.BaseMetricV3?.CvssV3.PrivilegesRequired.ToString(),
                        Scope = cveItem.Impact?.BaseMetricV3?.CvssV3.Scope.ToString(),
                        UserInteraction = cveItem.Impact?.BaseMetricV3?.CvssV3.UserInteraction.ToString(),
                    },
                    VectorString = cveItem.Impact?.BaseMetricV3?.CvssV3.VectorString,
                    BaseScore = cveItem.Impact?.BaseMetricV3?.CvssV3.BaseScore,
                    ExploitabilityScore = cveItem.Impact?.BaseMetricV3?.ExploitabilityScore,
                    ImpactScore = cveItem.Impact?.BaseMetricV3?.ImpactScore,
                    Impact = new Impact
                    {
                        Availability = cveItem.Impact?.BaseMetricV3?.CvssV3.AvailabilityImpact.ToString(),
                        Confidentiality = cveItem.Impact?.BaseMetricV3?.CvssV3.ConfidentialityImpact.ToString(),
                        Integrity = cveItem.Impact?.BaseMetricV3?.CvssV3.IntegrityImpact.ToString()
                    },
                    BaseSeverity = cveItem.Impact?.BaseMetricV3?.CvssV3.BaseSeverity.ToString(),
                    Version = cveItem.Impact?.BaseMetricV3?.CvssV3.Version.ToString()
                },
                References = cveItem.Cve.References.Reference_data.Select(r => new Reference
                {
                    Name = r.Name,
                    Refsource = r.Refsource,
                    Tags = r.Tags.ToArray(),
                    Url = r.Url
                }).ToArray(),
                Summary = cveItem.Cve.Description.Description_data.Select(s => s.Value).JoinToString(" "),
                VulnerableConfigurations = cpesTwoThree,
                Products = vendorsAndProducts
            }, vendorsAndProducts);
        }

        public static (CveMongoModel, VulnarableProducts[]) ToCveMongoModel(this CveItemNewApi cveItem)
        {
            Func<Cpe_match, CpeTwoThree> cpeMongo = (s) => new CpeTwoThree
            {
                CpeUri = s.Criteria,
                VersionEndExcluding = s.VersionEndExcluding,
                VersionEndIncluding = s.VersionEndIncluding,
                VersionStartExcluding = s.VersionStartExcluding,
                VersionStartIncluding = s.VersionStartIncluding,
                Vulnerable = s.Vulnerable
            };

            var cpesTwoThree = cveItem.Cve.Configurations?.SelectMany(s => s.Nodes).SelectMany(s => s.CpeMatch)
                                .Where(c => c.Vulnerable)
                                .Select(cpeMongo)
                                .ToArray() ?? Array.Empty<CpeTwoThree>();

            var vendorsAndProducts = cpesTwoThree.Select(s => s.CpeUri.Split(':', StringSplitOptions.RemoveEmptyEntries))
                .Select(v => new { Vendor = v[3], Software = v[4], Version = v[5], Os = v[10], Bitness = v[11] })
                .GroupBy(v => v.Vendor).Select(v => new VulnarableProducts
                {
                    Vendor = v.Key,
                    Softwares = v.GroupBy(s => s.Software).Select(g => new SoftwareWithVersions
                    {
                        SoftwareName = g.Key,
                        Versions = g.Select(v => new VersionOs { Version = v.Version, Os = v.Os, Bitness = v.Bitness })
                                    .DistinctBy(s => $"{s.Version} {s.Os} {s.Bitness}")
                                    .ToArray()
                    }).ToArray()
                }).ToArray();

            var cvssvTwo = cveItem.Cve.Metrics.CvssMetricV2?.FirstOrDefault();

            var cvssvThree = cveItem.Cve.Metrics.CvssMetricV30?.FirstOrDefault();

            var cvssvThreeOne = cveItem.Cve.Metrics.CvssMetricV31?.FirstOrDefault();

            return (new CveMongoModel
            {
                Published = cveItem.Cve.Published.UtcDateTime,
                Modified = cveItem.Cve.LastModified.UtcDateTime,
                CveId = cveItem.Cve.Id,
                Assigner = cveItem.Cve.SourceIdentifier,
                Cwes = cveItem.Cve.Weaknesses?.Select(p => new ProblemData
                {
                    Cwes = p.Description?.Select(d => d.Value).ToArray()
                }).ToArray() ?? Array.Empty<ProblemData>(),
                Cvss2 = new CvssTwo
                {
                    Access = new AccessTwo
                    {
                        Authentication = cvssvTwo?.CvssData?.Authentication.ToString(),
                        Complexity = cvssvTwo?.CvssData?.AccessComplexity.ToString(),
                        Vector = cvssvTwo?.CvssData?.AccessVector.ToString()
                    },
                    VectorString = cvssvTwo?.CvssData?.VectorString,
                    BaseScore = cvssvTwo?.CvssData?.BaseScore,
                    ExploitabilityScore = cvssvTwo?.ExploitabilityScore,
                    Severity = cvssvTwo?.BaseSeverity,
                    ImpactScore = cvssvTwo?.ImpactScore,
                    Impact = new Impact
                    {
                        Availability = cvssvTwo?.CvssData?.AvailabilityImpact.ToString(),
                        Confidentiality = cvssvTwo?.CvssData?.ConfidentialityImpact.ToString(),
                        Integrity = cvssvTwo?.CvssData?.IntegrityImpact.ToString()
                    },
                    Version = cvssvTwo?.CvssData?.Version.ToString()
                },
                Cvss3 = new CvssThree
                {
                    Attack = new AttackThree
                    {
                        Complexity = cvssvThree?.CvssData?.AttackComplexity.ToString(),
                        Vector = cvssvThree?.CvssData?.AttackVector.ToString(),
                        PrivilegesRequired = cvssvThree?.CvssData?.PrivilegesRequired.ToString(),
                        Scope = cvssvThree?.CvssData?.Scope.ToString(),
                        UserInteraction = cvssvThree?.CvssData?.UserInteraction.ToString(),
                    },
                    VectorString = cvssvThree?.CvssData?.VectorString,
                    BaseScore = cvssvThree?.CvssData?.BaseScore,
                    ExploitabilityScore = cvssvThree?.ExploitabilityScore,
                    ImpactScore = cvssvThree?.ImpactScore,
                    Impact = new Impact
                    {
                        Availability = cvssvThree?.CvssData?.AvailabilityImpact.ToString(),
                        Confidentiality = cvssvThree?.CvssData?.ConfidentialityImpact.ToString(),
                        Integrity = cvssvThree?.CvssData?.IntegrityImpact.ToString()
                    },
                    BaseSeverity = cvssvThree?.CvssData?.BaseSeverity.ToString(),
                    Version = cvssvThree?.CvssData?.Version.ToString()
                },
                Cvss31 = new CvssThree
                {
                    Attack = new AttackThree
                    {
                        Complexity = cvssvThreeOne?.CvssData?.AttackComplexity.ToString(),
                        Vector = cvssvThreeOne?.CvssData?.AttackVector.ToString(),
                        PrivilegesRequired = cvssvThreeOne?.CvssData?.PrivilegesRequired.ToString(),
                        Scope = cvssvThreeOne?.CvssData?.Scope.ToString(),
                        UserInteraction = cvssvThreeOne?.CvssData?.UserInteraction.ToString(),
                    },
                    VectorString = cvssvThreeOne?.CvssData?.VectorString,
                    BaseScore = cvssvThreeOne?.CvssData?.BaseScore,
                    ExploitabilityScore = cvssvThreeOne?.ExploitabilityScore,
                    ImpactScore = cvssvThreeOne?.ImpactScore,
                    Impact = new Impact
                    {
                        Availability = cvssvThreeOne?.CvssData?.AvailabilityImpact.ToString(),
                        Confidentiality = cvssvThreeOne?.CvssData?.ConfidentialityImpact.ToString(),
                        Integrity = cvssvThreeOne?.CvssData?.IntegrityImpact.ToString()
                    },
                    BaseSeverity = cvssvThreeOne?.CvssData?.BaseSeverity.ToString(),
                    Version = cvssvThreeOne?.CvssData?.Version.ToString()
                },
                References = cveItem.Cve.References?.Select(r => new Reference
                {
                    Name = r.Url,
                    Refsource = r.Source,
                    Tags = r.Tags?.ToArray() ?? Array.Empty<string>(),
                    Url = r.Url
                }).ToArray() ?? Array.Empty<Reference>(),
                Summary = cveItem.Cve.Descriptions?.FirstOrDefault()?.Value,
                VulnerableConfigurations = cpesTwoThree,
                Products = vendorsAndProducts
            }, vendorsAndProducts);
        }
    } 
}