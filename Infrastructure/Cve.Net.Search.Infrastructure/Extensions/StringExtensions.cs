using System;
using System.Collections.Generic;

namespace Cve.Infrastructure.Extensions
{
    public static class StringExtensions
    {
        public static string JoinToString(this IEnumerable<string> source, string separator = ", ")
            => string.Join(separator, source).TrimEnd(separator);

        public static string TrimEnd(this string input, string suffix)
        {
            if (input.EndsWith(suffix, StringComparison.Ordinal))
                input = input.Substring(0, input.LastIndexOf(suffix, StringComparison.Ordinal));

            return input;
        }
    }
}
