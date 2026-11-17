using System.Text.RegularExpressions;
using Cve.Infrastructure.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using FluentAssertions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using Xunit;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Golden tests for keyword search (ticket T02): every case from the fixture is
/// executed through the same filter the search endpoints use (KeywordFilterBuilder),
/// and the matched CVE ids must equal the hand-written expected ids.
/// The filter is evaluated against the fixture records by rendering the MongoDB
/// filter and applying its per-field regexes — the observable substring-matching
/// behaviour, not the builder's internals.
/// </summary>
public class KeywordGoldenDatasetTests
{
    [Fact]
    public void Search_GoldenCases_MatchesExactlyTheExpectedIds()
    {
        foreach (var goldenCase in KeywordGoldenDataset.Cases)
        {
            var matchedIds = Search(goldenCase.Keyword);

            matchedIds.Should().Equal(goldenCase.ExpectedCveIds,
                $"keyword '{goldenCase.Keyword}' ({goldenCase.Why})");
        }
    }

    [Fact]
    public void Search_NegativeGoldenCases_MatchesNothing()
    {
        foreach (var negativeCase in KeywordGoldenDataset.NegativeCases)
        {
            Search(negativeCase.Keyword).Should().BeEmpty(
                $"keyword '{negativeCase.Keyword}' ({negativeCase.Why}) must not match any fixture record");
        }
    }

    [Fact]
    public void Search_EmptyKeyword_MatchesEveryRecord()
    {
        // Substring semantics: the empty phrase is contained in every field value.
        // At the HTTP layer the CVE search routes reject empty keywords via
        // [Required][MinLength(1)], so this only pins the filter's own behaviour.
        var matchedIds = Search(string.Empty);

        matchedIds.Should().Equal(KeywordGoldenDataset.Records.Select(r => r.CveId));
    }

    [Fact]
    public void Search_NullKeyword_ThrowsArgumentNullException()
    {
        // Current contract: null is not a search phrase; the routes never pass one
        // ([Required][MinLength(1)]), and the builder treats null as a programming error.
        var act = () => KeywordFilterBuilder.Build<CveMongoModel>(null!, c => c.CveId, c => c.Summary);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Fixture_ContainsNoDuplicateIdsOrUnreferencedGoldenExpectations()
    {
        KeywordGoldenDataset.Records.Select(r => r.CveId).Should().OnlyHaveUniqueItems();

        // Every record must be exercised by at least one golden case so the dataset
        // cannot silently rot into records no search ever touches.
        var referenced = KeywordGoldenDataset.Cases
            .SelectMany(c => c.ExpectedCveIds)
            .ToHashSet();

        KeywordGoldenDataset.Records
            .Where(r => !referenced.Contains(r.CveId))
            .Select(r => r.CveId)
            .Should().BeEmpty("every fixture record should appear in at least one expected result");
    }

    /// <summary>
    /// Runs the golden keyword through the production filter and returns the ids of
    /// the fixture records the filter matches.
    /// </summary>
    private static IReadOnlyList<string> Search(string keyword)
    {
        var fieldRegexes = ExtractFieldRegexes(
            KeywordFilterBuilder.Build<CveMongoModel>(keyword, c => c.CveId, c => c.Summary));

        return KeywordGoldenDataset.Records
            .Where(record => Matches(record, fieldRegexes))
            .Select(record => record.CveId)
            .ToList();
    }

    private static bool Matches(KeywordGoldenDataset.GoldenCve record,
        IReadOnlyList<(string Field, Regex Regex)> fieldRegexes)
    {
        return fieldRegexes.Any(match =>
            match.Regex.IsMatch(match.Field == "CveId" ? record.CveId : record.Summary));
    }

    private static IReadOnlyList<(string Field, Regex Regex)> ExtractFieldRegexes(
        FilterDefinition<CveMongoModel> filter)
    {
        var rendered = Render(filter);

        return rendered["$or"].AsBsonArray
            .Select(alternative => alternative.AsBsonDocument)
            .Select(alternative =>
            {
                var field = alternative.GetElement(0);
                var renderedRegex = (BsonRegularExpression)field.Value;
                var options = renderedRegex.Options == "i" ? RegexOptions.IgnoreCase : RegexOptions.None;
                return (field.Name, new Regex(renderedRegex.Pattern, options));
            })
            .ToList();
    }

    private static BsonDocument Render(FilterDefinition<CveMongoModel> filter)
    {
        var serializer = BsonSerializer.SerializerRegistry.GetSerializer<CveMongoModel>();
        return filter.Render(new RenderArgs<CveMongoModel>(serializer, BsonSerializer.SerializerRegistry));
    }
}
