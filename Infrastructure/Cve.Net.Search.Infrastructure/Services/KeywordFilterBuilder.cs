using System.Text.RegularExpressions;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Linq.Expressions;

namespace Cve.Infrastructure.Services;

/// <summary>
/// Builds the keyword filter used by the paged list endpoints: one phrase,
/// case-insensitive substring match, hitting any of the given fields.
/// </summary>
public static class KeywordFilterBuilder
{
    public static FilterDefinition<T> Build<T>(string keyword, params Expression<Func<T, string>>[] fields)
    {
        var regex = new BsonRegularExpression(Regex.Escape(keyword), "i");
        return Builders<T>.Filter.Or(fields.Select(field =>
        {
            var fieldDef = new ExpressionFieldDefinition<T>(field);
            return Builders<T>.Filter.Regex(fieldDef, regex);
        }));
    }
}
