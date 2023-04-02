using System;
using System.Collections.Generic;

namespace Cve.Net.Search.Domain.Database.MongoModels.Extensions
{
    internal static class StringExtensions
    {
        internal static string JoinToString(this IEnumerable<string> source, string separator = ", ")
            => string.Join(separator, source).TrimEnd(separator);

        internal static string TrimEnd(this string input, string suffix)
        {
            if (input.EndsWith(suffix, StringComparison.Ordinal))
                input = input.Substring(0, input.LastIndexOf(suffix, StringComparison.Ordinal));

            return input;
        }
    }
}
