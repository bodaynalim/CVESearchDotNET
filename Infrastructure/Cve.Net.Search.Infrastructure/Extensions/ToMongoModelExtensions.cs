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

namespace Cve.Infrastructure.Extensions;

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

    public static (CveMongoModel, VulnerableProducts[]) ToCveMongoModel(this CveItemModel cveItem)
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

        var vendorsAndProducts = GroupVulnerableProducts(cpesTwoThree);

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
            Cvss2 = MapCvssTwo(cveItem.Impact?.BaseMetricV2),
            Cvss3 = MapCvssThree(cveItem.Impact?.BaseMetricV3),
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

    public static (CveMongoModel, VulnerableProducts[]) ToCveMongoModel(this CveItemNewApi cveItem)
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

        var vendorsAndProducts = GroupVulnerableProducts(cpesTwoThree);

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
            Cvss2 = MapCvssTwo(cvssvTwo),
            Cvss3 = MapCvssThree(cvssvThree),
            Cvss31 = MapCvssThree(cvssvThreeOne),
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

    #region Private Helpers

    private static VulnerableProducts[] GroupVulnerableProducts(CpeTwoThree[] cpes)
    {
        return cpes.Select(s => s.CpeUri.Split(':', StringSplitOptions.RemoveEmptyEntries))
            .Select(v => new { Vendor = v[3], Software = v[4], Version = v[5], Os = v[10], Bitness = v[11] })
            .GroupBy(v => v.Vendor)
            .Select(v => new VulnerableProducts
            {
                Vendor = v.Key,
                Softwares = v.GroupBy(s => s.Software)
                    .Select(g => new SoftwareWithVersions
                    {
                        SoftwareName = g.Key,
                        Versions = g.Select(v => new VersionOs { Version = v.Version, Os = v.Os, Bitness = v.Bitness })
                                    .DistinctBy(s => $"{s.Version} {s.Os} {s.Bitness}")
                                    .ToArray()
                    }).ToArray()
            }).ToArray();
    }

    private static CvssTwo MapCvssTwo(BaseMetricV2 metric)
    {
        if (metric?.CvssV2 == null)
            return null;

        return new CvssTwo
        {
            Access = new AccessTwo
            {
                Authentication = metric.CvssV2.Authentication.ToString(),
                Complexity = metric.CvssV2.AccessComplexity.ToString(),
                Vector = metric.CvssV2.AccessVector.ToString()
            },
            VectorString = metric.CvssV2.VectorString,
            BaseScore = metric.CvssV2.BaseScore,
            ExploitabilityScore = metric.ExploitabilityScore,
            Severity = metric.Severity,
            ImpactScore = metric.ImpactScore,
            Impact = new Impact
            {
                Availability = metric.CvssV2.AvailabilityImpact.ToString(),
                Confidentiality = metric.CvssV2.ConfidentialityImpact.ToString(),
                Integrity = metric.CvssV2.IntegrityImpact.ToString()
            },
            Version = metric.CvssV2.Version.ToString()
        };
    }

    private static CvssTwo MapCvssTwo(CvssV2 metric)
    {
        if (metric?.CvssData == null)
            return null;

        return new CvssTwo
        {
            Access = new AccessTwo
            {
                Authentication = metric.CvssData.Authentication.ToString(),
                Complexity = metric.CvssData.AccessComplexity.ToString(),
                Vector = metric.CvssData.AccessVector.ToString()
            },
            VectorString = metric.CvssData.VectorString,
            BaseScore = metric.CvssData.BaseScore,
            ExploitabilityScore = metric.ExploitabilityScore,
            Severity = metric.BaseSeverity,
            ImpactScore = metric.ImpactScore,
            Impact = new Impact
            {
                Availability = metric.CvssData.AvailabilityImpact.ToString(),
                Confidentiality = metric.CvssData.ConfidentialityImpact.ToString(),
                Integrity = metric.CvssData.IntegrityImpact.ToString()
            },
            Version = metric.CvssData.Version.ToString()
        };
    }

    private static CvssThree MapCvssThree(BaseMetricV3 metric)
    {
        if (metric?.CvssV3 == null)
            return null;

        return new CvssThree
        {
            Attack = new AttackThree
            {
                Complexity = metric.CvssV3.AttackComplexity.ToString(),
                Vector = metric.CvssV3.AttackVector.ToString(),
                PrivilegesRequired = metric.CvssV3.PrivilegesRequired.ToString(),
                Scope = metric.CvssV3.Scope.ToString(),
                UserInteraction = metric.CvssV3.UserInteraction.ToString(),
            },
            VectorString = metric.CvssV3.VectorString,
            BaseScore = metric.CvssV3.BaseScore,
            ExploitabilityScore = metric.ExploitabilityScore,
            ImpactScore = metric.ImpactScore,
            Impact = new Impact
            {
                Availability = metric.CvssV3.AvailabilityImpact.ToString(),
                Confidentiality = metric.CvssV3.ConfidentialityImpact.ToString(),
                Integrity = metric.CvssV3.IntegrityImpact.ToString()
            },
            BaseSeverity = metric.CvssV3.BaseSeverity.ToString(),
            Version = metric.CvssV3.Version.ToString()
        };
    }

    private static CvssThree MapCvssThree(CvssV30 metric)
    {
        if (metric?.CvssData == null)
            return null;

        return new CvssThree
        {
            Attack = new AttackThree
            {
                Complexity = metric.CvssData.AttackComplexity.ToString(),
                Vector = metric.CvssData.AttackVector.ToString(),
                PrivilegesRequired = metric.CvssData.PrivilegesRequired.ToString(),
                Scope = metric.CvssData.Scope.ToString(),
                UserInteraction = metric.CvssData.UserInteraction.ToString(),
            },
            VectorString = metric.CvssData.VectorString,
            BaseScore = metric.CvssData.BaseScore,
            ExploitabilityScore = metric.ExploitabilityScore,
            ImpactScore = metric.ImpactScore,
            Impact = new Impact
            {
                Availability = metric.CvssData.AvailabilityImpact.ToString(),
                Confidentiality = metric.CvssData.ConfidentialityImpact.ToString(),
                Integrity = metric.CvssData.IntegrityImpact.ToString()
            },
            BaseSeverity = metric.CvssData.BaseSeverity.ToString(),
            Version = metric.CvssData.Version.ToString()
        };
    }

    private static CvssThree MapCvssThree(CvssV31 metric)
    {
        if (metric?.CvssData == null)
            return null;

        return new CvssThree
        {
            Attack = new AttackThree
            {
                Complexity = metric.CvssData.AttackComplexity.ToString(),
                Vector = metric.CvssData.AttackVector.ToString(),
                PrivilegesRequired = metric.CvssData.PrivilegesRequired.ToString(),
                Scope = metric.CvssData.Scope.ToString(),
                UserInteraction = metric.CvssData.UserInteraction.ToString(),
            },
            VectorString = metric.CvssData.VectorString,
            BaseScore = metric.CvssData.BaseScore,
            ExploitabilityScore = metric.ExploitabilityScore,
            ImpactScore = metric.ImpactScore,
            Impact = new Impact
            {
                Availability = metric.CvssData.AvailabilityImpact.ToString(),
                Confidentiality = metric.CvssData.ConfidentialityImpact.ToString(),
                Integrity = metric.CvssData.IntegrityImpact.ToString()
            },
            BaseSeverity = metric.CvssData.BaseSeverity.ToString(),
            Version = metric.CvssData.Version.ToString()
        };
    }

    #endregion
}
