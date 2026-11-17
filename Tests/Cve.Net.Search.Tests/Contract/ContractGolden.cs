// T04 contract snapshots. Golden JSON below is HAND-AUTHORED and pinned to ADR-0001:
// every property name on the wire is camelCase while the C# records are PascalCase.
// Property ORDER follows the C# declaration order (Newtonsoft preserves it), and MVC's
// contract resolver INCLUDES null properties (NullValueHandling.Include) — both are
// pinned. If a change here is intended, it is a wire-contract change and must be
// reviewed against ADR-0001 and mirrored in CveUI fixtures.
namespace Cve.Net.Search.Tests;

internal static class ContractGolden
{
    /// <summary>CveController: Get / Search / GetAll / SearchByKeyword / last-published / last-modified.</summary>
    public const string CveViewModel = """
{
  "cveId": "CVE-2024-1234",
  "assigner": "mitre",
  "published": "2024-01-15T00:00:00",
  "modified": "2024-02-01T00:00:00",
  "cwes": [
    "CWE-79"
  ],
  "summary": "Cross-site scripting in ExampleApp.",
  "cvss2": {
    "access": {
      "vector": "Network",
      "complexity": "Low",
      "authentication": "None"
    },
    "impact": {
      "confidentiality": "Partial",
      "integrity": "Partial",
      "availability": "None"
    },
    "baseScore": 4.3,
    "exploitabilityScore": 8.6,
    "impactScore": 2.9,
    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
    "severity": "MEDIUM",
    "version": "2.0"
  },
  "cvss3": {
    "attack": {
      "vector": "Network",
      "complexity": "Low",
      "privilegesRequired": "None",
      "userInteraction": "Required",
      "scope": "Unchanged"
    },
    "impact": {
      "confidentiality": "High",
      "integrity": "High",
      "availability": "None"
    },
    "baseScore": 7.5,
    "exploitabilityScore": 2.8,
    "impactScore": 5.5,
    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "baseSeverity": "HIGH",
    "version": "3.0"
  },
  "referencesUrls": [
    "https://example.com/advisory/CVE-2024-1234"
  ],
  "vulnerableConfigurations": [
    "cpe:2.3:a:example:example_app:1.0:*:*:*:*:*:*:*"
  ]
}
""";

    /// <summary>
    /// Pins that a CVE without any CVSS data still carries the keys, as explicit nulls
    /// (MVC Newtonsoft default NullValueHandling.Include). Renaming or dropping these
    /// keys would break CveUI fixtures even for CVSS-less records.
    /// </summary>
    public const string CveViewModelWithoutCvss = """
{
  "cveId": "CVE-2024-5678",
  "assigner": "mitre",
  "published": "2024-03-01T00:00:00",
  "modified": "2024-03-02T00:00:00",
  "cwes": [],
  "summary": "Insufficient information, no scoring available.",
  "cvss2": null,
  "cvss3": null,
  "referencesUrls": [],
  "vulnerableConfigurations": []
}
""";

    /// <summary>CveController: search-count / all-count. Same shape as the CWE count VM.</summary>
    public const string CveSearchCountViewModel = """
{
  "total": 42
}
""";

    /// <summary>CweController: Get / ListAll / SearchByKeyword.</summary>
    public const string CweViewModel = """
{
  "cweId": "79",
  "name": "Cross-site Scripting",
  "description": "The product does not neutralize user-controllable input.",
  "status": "Stable",
  "abstraction": "Variant",
  "relatedCwes": [
    "1004"
  ]
}
""";

    /// <summary>CweController: all-count / search-count. Deliberately a separate type from CveSearchCountViewModel.</summary>
    public const string CweSearchCountViewModel = """
{
  "total": 319
}
""";

    /// <summary>
    /// CapecController: Get. Note: ExecutionFlowTypeAttack.Techniques is a public FIELD,
    /// not a property — yet Newtonsoft's DefaultContractResolver (MVC default) DOES
    /// serialize public fields, and it orders fields BEFORE properties, so "techniques"
    /// is part of the wire contract and comes first inside each execution-flow entry.
    /// Pinned deliberately so CveUI never expects a different key set.
    /// </summary>
    public const string CapecViewModel = """
{
  "name": "Test Attack Pattern",
  "capecId": "1",
  "summary": "An adversary induces a fault.",
  "prerequisites": [
    "Access to the target system"
  ],
  "solutions": [
    "Input validation"
  ],
  "relatedCapecs": [
    "2"
  ],
  "relatedCwes": [
    "79"
  ],
  "severity": "High",
  "taxonomy": [
    {
      "name": "ATTACK",
      "entryId": "1",
      "entryName": "Test Entry",
      "url": "https://example.com/capec/1"
    }
  ],
  "likelyhoodAttack": "Medium",
  "executionFlowTypeAttacks": [
    {
      "techniques": [
        "Probe"
      ],
      "step": "1",
      "phase": "Explore",
      "descriptionField": "Adversary probes the target."
    }
  ]
}
""";

    /// <summary>VendorsController: GetProductsByVendor.</summary>
    public const string VendorProductsViewModel = """
{
  "vendor": "example",
  "softwares": [
    "example_app"
  ]
}
""";

    /// <summary>VendorsController: GetAllVendors returns a bare JSON string array.</summary>
    public const string VendorNameList = """
[
  "akamai",
  "example"
]
""";
}
