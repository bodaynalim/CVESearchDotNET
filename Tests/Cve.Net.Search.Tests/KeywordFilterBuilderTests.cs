using System.Text.RegularExpressions;
using Cve.Infrastructure.Services;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using Cve.Net.Search.Domain.Database.MongoModels.Cwe;
using FluentAssertions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using Xunit;

namespace Cve.Net.Search.Tests;

public class KeywordFilterBuilderTests
{
    private static BsonDocument Render<T>(FilterDefinition<T> filter)
    {
        var serializer = BsonSerializer.SerializerRegistry.GetSerializer<T>();
        return filter.Render(new RenderArgs<T>(serializer, BsonSerializer.SerializerRegistry));
    }

    [Fact]
    public void Build_WithTwoFields_ProducesOrOfCaseInsensitiveRegexes()
    {
        var filter = KeywordFilterBuilder.Build<CveMongoModel>("overflow", c => c.CveId, c => c.Summary);

        Render(filter).ToJson().Should().Be(
            new BsonDocument("$or", new BsonArray
            {
                RegexBson("overflow"),
                RegexBson("overflow", "Summary"),
            }).ToJson());
    }

    [Fact]
    public void Build_EscapesRegexMetacharactersSoKeywordsMatchLiterally()
    {
        var filter = KeywordFilterBuilder.Build<CveMongoModel>("c.((v*", c => c.CveId);

        var rendered = (BsonRegularExpression)Render(filter)["$or"][0]["CveId"];
        var pattern = rendered.Pattern;
        var options = rendered.Options;
        var regex = new Regex(pattern, options == "i" ? RegexOptions.IgnoreCase : RegexOptions.None);

        regex.IsMatch("CVE-2018-0001") /* unescaped pattern would match too */ .Should().BeFalse();

        // "c" followed by ".((v*" as literal text must match the escaped pattern:
        regex.IsMatch("ac.((v*zz").Should().BeTrue();
    }

    [Fact]
    public void Build_WithSingleField_ProducesDirectRegexWithoutOr()
    {
        var filter = KeywordFilterBuilder.Build<CveMongoModel>("heap", c => c.Summary);

        Render(filter).ToJson().Should().Be(
            new BsonDocument("$or", new BsonArray { RegexBson("heap", "Summary") }).ToJson());
    }

    [Fact]
    public void Build_CweFields_MatchesIdOrNameCaseInsensitively()
    {
        var filter = KeywordFilterBuilder.Build<CweMongoModel>("script", c => c.CweId, c => c.Name);

        var doc = Render(filter);
        doc.ToJson().Should().Contain("CweId");
        doc.ToJson().Should().Contain("Name");
        doc.ToJson().Should().Contain(CaseInsensitiveRegexPattern("script"));
    }

    private static string CaseInsensitiveRegexPattern(string keyword) => Regex.Escape(keyword);

    private static BsonDocument RegexBson(string pattern, string field = "CveId") => new(
        field,
        new BsonDocument("$regularExpression", new BsonDocument { ["pattern"] = pattern, ["options"] = "i" }));
}
