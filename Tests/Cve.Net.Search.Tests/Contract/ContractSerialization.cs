using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Cve.Net.Search.Tests;

/// <summary>
/// Serialization seam for the T04 contract snapshots. Controllers return view models
/// serialized by ASP.NET Core MVC's Newtonsoft stack (Program.cs calls
/// AddNewtonsoftJson() with no configuration), so the framework defaults captured in
/// <see cref="MvcNewtonsoftJsonOptions"/> ARE the wire contract (ADR-0001).
/// Instantiating the options object reproduces exactly those settings — including the
/// camelCase naming strategy — without standing up a WebApplicationFactory or a Mongo connection.
/// </summary>
internal static class ContractSerialization
{
    public static JsonSerializerSettings MvcSettings { get; } = new MvcNewtonsoftJsonOptions().SerializerSettings;

    public static string Serialize(object viewModel) => JsonConvert.SerializeObject(viewModel, MvcSettings);

    /// <summary>
    /// Whitespace is deliberately not part of the pinned contract (MVC's serialization
    /// formatting is not negotiated with CveUI), so both sides are compared as JTokens
    /// rendered indent-pretty. This keeps a failing test's diff a readable, aligned JSON
    /// dump instead of one long single-line string.
    /// </summary>
    public static string FormatForDiff(string json) =>
        JsonConvert.SerializeObject(JsonConvert.DeserializeObject(json)!, Formatting.Indented)
            .Replace("\r\n", "\n");

    /// <summary>
    /// Golden constants live in raw string literals whose newlines follow the checkout's
    /// line-ending normalization (CRLF on Windows with autocrlf, LF in CI). The contract
    /// is the JSON, not the checkout encoding, so comparisons must normalize newlines.
    /// </summary>
    public static string NormalizeNewlines(string golden) => golden.Replace("\r\n", "\n");
}
