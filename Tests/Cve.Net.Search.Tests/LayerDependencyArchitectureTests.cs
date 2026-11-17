using Cve.Infrastructure.AutoMapper;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Common.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Domain.ViewModels;
using CVESearch.Controllers;
using FluentAssertions;
using Xunit;

namespace Cve.Net.Search.Tests;

// T05 (docs/tickets/T05-architecture-tests.md): mechanizes the layering rules from
// docs/CODING_STANDARDS.md section 2 (Layering, hard). Chosen deliberately over
// NetArchTest.Rules to add zero new NuGet dependencies: the rules only concern
// project-to-project references, which are fully visible in the compile-time
// reference list of each root assembly (GetReferencedAssemblies).
//
// Adding a forbidden ProjectReference makes the root assembly's reference list
// contain the forbidden project and the test fails with an explicit message.
public class LayerDependencyArchitectureTests
{
    /// <summary>
    /// Documented known violations of the layering rules (T05 acceptance criteria).
    /// Each entry is "Layer &gt; Dependency", e.g. "Cve.Net.Search.Domain.Common &gt; Cve.Net.Search.Infrastructure".
    /// Every entry must carry a comment explaining why it exists and the ticket that will fix it.
    /// The list is currently EMPTY — no layering violations exist in the codebase.
    /// </summary>
    private static readonly string[] KnownViolations =
    {
        // (none)
    };

    /// <summary>
    /// One entry per layer assembly: the root type pinning the assembly (so renames
    /// surface as a missing-type compile error rather than a silently skipped rule)
    /// and the prefixes of the project assemblies this layer must never reference.
    /// </summary>
    private static readonly (Type RootType, string[] ForbiddenDependencies)[] Rules =
    {
        // Domain (Common / Database / ViewModels) = plain models and records — nothing above it.
        (typeof(CvssThree), [DomainLayer.Application, DomainLayer.Infrastructure, DomainLayer.Web]),
        (typeof(CveMongoModel), [DomainLayer.Application, DomainLayer.Infrastructure, DomainLayer.Web]),
        (typeof(CveViewModel), [DomainLayer.Application, DomainLayer.Infrastructure, DomainLayer.Web]),
        // Application = service interfaces + orchestration — must stay independent of Infrastructure/Web.
        (typeof(ICveMongoService), [DomainLayer.Infrastructure, DomainLayer.Web]),
        // Infrastructure implements Application interfaces — referencing Application is allowed
        // (docs/CODING_STANDARDS.md section 8). Web and Application themselves impose no rules.
        (typeof(VulnerabilitiesProfile), []),
        (typeof(CveController), []),
    };

    private const string ProjectAssemblyPrefix = "Cve.Net.Search.";

    private static class DomainLayer
    {
        public const string Application = "Cve.Net.Search.Application";
        public const string Infrastructure = "Cve.Net.Search.Infrastructure";
        public const string Web = "Cve.Net.Search.Web";
    }

    [Fact]
    public void Layering_WithCurrentProjectReferences_HasNoUndocumentedForbiddenReferences()
    {
        var violations = Rules
            .SelectMany(rule => ForbiddenReferencesOf(rule.RootType, rule.ForbiddenDependencies))
            .Except(KnownViolations)
            .ToList();

        violations.Should().BeEmpty(
            "the layering rules in docs/CODING_STANDARDS.md section 2 are hard rules: " +
            "remove the forbidden ProjectReference from the csproj (or, if a violation is a " +
            "pre-existing documented exception, add it to KnownViolations with a comment and a burn-down ticket)");
    }

    [Fact]
    public void Layering_KnownViolations_AllReferencedByCurrentCode()
    {
        // Guards KnownViolations from rotting: a documented exception whose fix has landed
        // must be removed from the list instead of lingering.
        var current = Rules
            .SelectMany(rule => ForbiddenReferencesOf(rule.RootType, rule.ForbiddenDependencies))
            .ToList();

        KnownViolations
            .Where(documented => !current.Contains(documented))
            .Should().BeEmpty("documented violations in KnownViolations must be removed once fixed");
    }

    private static IEnumerable<string> ForbiddenReferencesOf(Type rootType, string[] forbiddenDependencies)
    {
        var layerAssembly = rootType.Assembly.GetName().Name!;
        var edges = new HashSet<string>();
        Visit(rootType.Assembly, edges);
        return edges.Where(edge => forbiddenDependencies.Any(dependency => EdgeTargetIs(edge, dependency)))
            .Select(edge => $"{layerAssembly} > {edge}")
            .OrderBy(edge => edge, StringComparer.Ordinal);
    }

    /// <summary>
    /// Walks the compile-time reference graph and records every edge between project
    /// assemblies (names starting with <see cref="ProjectAssemblyPrefix"/>) as "Source > Target".
    /// </summary>
    private static void Visit(System.Reflection.Assembly assembly, HashSet<string> edges)
    {
        foreach (var referenced in assembly.GetReferencedAssemblies())
        {
            var name = referenced.Name!;
            if (!name.StartsWith(ProjectAssemblyPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            if (!edges.Add($"{assembly.GetName().Name} > {name}"))
            {
                continue;
            }

            // Only follow the edge when the referenced project assembly is loadable in
            // the test context; the name comparison above is what the rules need anyway.
            try
            {
                Visit(System.Reflection.Assembly.Load(referenced), edges);
            }
            catch (System.IO.FileNotFoundException)
            {
                // The reference list is compile-time data; an unloadable entry still
                // counts as a reference and has already been recorded above.
            }
        }
    }

    private static bool EdgeTargetIs(string edge, string dependency) =>
        edge.EndsWith($" > {dependency}", StringComparison.Ordinal);
}
