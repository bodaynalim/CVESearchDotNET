/**
 * DTO shapes mirrored from the REST API's C# view models.
 * The API serializes C# records with PascalCase property names (no camelCase policy).
 */

export interface CvssTwo {
  BaseScore?: number | null;
  ExploitabilityScore?: number | null;
  ImpactScore?: number | null;
  VectorString?: string | null;
  Severity?: string | null;
  Version?: string | null;
}

export interface CvssThree {
  BaseScore?: number | null;
  ExploitabilityScore?: number | null;
  ImpactScore?: number | null;
  VectorString?: string | null;
  BaseSeverity?: string | null;
  Version?: string | null;
}

export interface CveViewModel {
  CveId: string;
  Assigner: string;
  Published: string;
  Modified: string;
  Cwes: string[];
  Summary: string;
  Cvss2?: CvssTwo | null;
  Cvss3?: CvssThree | null;
  ReferencesUrls: string[];
  VulnerableConfigurations: string[];
}

export interface CveSearchCount {
  Total: number;
}

export interface VendorProductsViewModel {
  Vendor: string;
  Softwares: string[];
}

export interface CweViewModel {
  CweId: string;
  Name: string;
  Description: string;
}

export interface CapecViewModel {
  Name: string;
  CapecId: string;
  Summary: string;
  Prerequisites: string[];
  Solutions: string[];
  RelatedCapecs: string[];
  RelatedCwes: string[];
  Severity: string;
  Taxonomy: unknown[];
  LikelyhoodAttack: string;
  ExecutionFlowTypeAttacks: unknown[];
}
