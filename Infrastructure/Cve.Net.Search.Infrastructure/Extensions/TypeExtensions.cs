using System;
using System.ComponentModel;
using System.Reflection;

namespace Cve.Net.Search.Domain.Database.Extensions
{
    public static class TypeExtensions
    {
        public static string GetFieldDescription(this Type type, string fieldName)
        {
            var descriptionAttribute = type
                    .GetMember(fieldName)[0]
                    .GetCustomAttribute(typeof(DescriptionAttribute), false) as DescriptionAttribute;

            return descriptionAttribute?.Description ?? fieldName;
        }
    }
}
