/**
 * DTO shapes mirrored from the REST API's JSON payloads.
 * The API serializes with a camelCase contract resolver (Newtonsoft default
 * via AddNewtonsoftJson, overriding the System.Text.Json options), verified
 * against live endpoints. Keep these in sync with the C# view models AND
 * their JSON casing.
 */

export interface CvssTwo {
  baseScore?: number | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  vectorString?: string | null;
  severity?: string | null;
  version?: string | null;
}

export interface CvssThree {
  baseScore?: number | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  vectorString?: string | null;
  baseSeverity?: string | null;
  version?: string | null;
}

export interface CveViewModel {
  cveId: string;
  assigner: string;
  published: string;
  modified: string;
  cwes: string[];
  summary: string;
  cvss2?: CvssTwo | null;
  cvss3?: CvssThree | null;
  referencesUrls: string[];
  vulnerableConfigurations: string[];
}

export interface CveSearchCount {
  total: number;
}

export interface VendorProductsViewModel {
  vendor: string;
  softwares: string[];
}

export interface CweViewModel {
  cweId: string;
  name: string;
  description: string;
}

export interface CapecViewModel {
  name: string;
  capecId: string;
  summary: string;
  prerequisites: string[];
  solutions: string[];
  relatedCapecs: string[];
  relatedCwes: string[];
  severity: string;
  taxonomy: unknown[];
  likelyhoodAttack: string;
  executionFlowTypeAttacks: unknown[];
}
