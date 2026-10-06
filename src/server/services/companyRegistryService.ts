// ==============================================================================
// COMPANY REGISTRY LOCAL REFERENCE SERVICE
// NOTE: This service uses a LOCAL REFERENCE DATASET only.
// Live MCA21 statutory API is NOT configured. All results are labeled LOCAL_REFERENCE.
// Do NOT treat results as live statutory verification.
// ==============================================================================
import crypto from 'crypto';
import { EvidenceItem } from '../../types';
import { normalizeCompanyName } from '../utils/normalizer';

export type RegistryStatus =
  | "LOCAL_REFERENCE_FOUND"
  | "VERIFIED_REGISTERED"
  | "REGISTERED_NAME_MISMATCH"
  | "NOT_FOUND"
  | "INSUFFICIENT_DATA"
  | "SOURCE_UNAVAILABLE";

export interface RegistryRecord {
  cin?: string;
  llpin?: string;
  legal_name: string;
  brand_name?: string;
  parent_company?: string;
  status: "ACTIVE" | "STRIKE_OFF" | "UNDER_LIQUIDATION" | "DORMANT" | "UNKNOWN";
  company_type: "PUBLIC_LIMITED" | "PRIVATE_LIMITED" | "LLP" | "ONE_PERSON" | "FOREIGN_BRANCH" | "OTHER";
  registration_state?: string;
  incorporation_year?: number;
  official_domain?: string;
  source: string;
  source_type: "LOCAL_REFERENCE" | "LOCAL_REFERENCE_ONLY" | "CACHED_REGISTRY" | "FALLBACK_VERIFIER";
  retrieved_at: string;
  confidence: number;
}

export interface RegistryLookupResult {
  query: string;
  normalized_query: string;
  status: RegistryStatus;
  record?: RegistryRecord;
  evidence: EvidenceItem[];
  explanation: string;
  brand_vs_legal_analysis?: {
    is_brand_alias: boolean;
    claimed_name: string;
    registered_legal_name: string;
    parent_entity?: string;
  };
}

// CIN pattern: [U/L][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}
const CIN_REGEX = /^[UL][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$/i;
// LLPIN pattern: [A-Z]{3}-[0-9]{4} or [0-9]{7}
const LLPIN_REGEX = /^[A-Z]{3}-[0-9]{4}$|^[0-9]{7}$/i;

// LOCAL REFERENCE DATASET — Not a live MCA21 query. Fixed snapshot date.
// These records are sourced from public corporate disclosures and provided
// as reference only. Do not treat as live statutory verification.
const LOCAL_REFERENCE_RETRIEVED_AT = "2025-01-01T00:00:00.000Z";

const LOCAL_REFERENCE_REGISTRY: Record<string, RegistryRecord> = {
  "indigo": {
    cin: "L62100DL2004PLC129768",
    legal_name: "InterGlobe Aviation Limited",
    brand_name: "IndiGo",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Delhi / Haryana",
    incorporation_year: 2004,
    official_domain: "goindigo.in",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "interglobe aviation": {
    cin: "L62100DL2004PLC129768",
    legal_name: "InterGlobe Aviation Limited",
    brand_name: "IndiGo",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Delhi / Haryana",
    incorporation_year: 2004,
    official_domain: "goindigo.in",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "tata motors": {
    cin: "L28920MH1945PLC004520",
    legal_name: "Tata Motors Limited",
    brand_name: "Tata Motors",
    parent_company: "Tata Sons Private Limited",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Maharashtra",
    incorporation_year: 1945,
    official_domain: "tatamotors.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "tcs": {
    cin: "L22210MH1995PLC084781",
    legal_name: "Tata Consultancy Services Limited",
    brand_name: "TCS",
    parent_company: "Tata Sons Private Limited",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Maharashtra",
    incorporation_year: 1995,
    official_domain: "tcs.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "tata consultancy": {
    cin: "L22210MH1995PLC084781",
    legal_name: "Tata Consultancy Services Limited",
    brand_name: "TCS",
    parent_company: "Tata Sons Private Limited",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Maharashtra",
    incorporation_year: 1995,
    official_domain: "tcs.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "infosys": {
    cin: "L85110KA1981PLC013115",
    legal_name: "Infosys Limited",
    brand_name: "Infosys",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Karnataka",
    incorporation_year: 1981,
    official_domain: "infosys.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "wipro": {
    cin: "L32102KA1945PLC020800",
    legal_name: "Wipro Limited",
    brand_name: "Wipro",
    status: "ACTIVE",
    company_type: "PUBLIC_LIMITED",
    registration_state: "Karnataka",
    incorporation_year: 1945,
    official_domain: "wipro.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "microsoft": {
    cin: "U72200DL1998PTC095147",
    legal_name: "Microsoft Corporation (India) Private Limited",
    brand_name: "Microsoft",
    parent_company: "Microsoft Corporation (US)",
    status: "ACTIVE",
    company_type: "PRIVATE_LIMITED",
    registration_state: "Delhi",
    incorporation_year: 1998,
    official_domain: "microsoft.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "google": {
    cin: "U72900KA2003PTC033028",
    legal_name: "Google India Private Limited",
    brand_name: "Google",
    parent_company: "Alphabet Inc. (US)",
    status: "ACTIVE",
    company_type: "PRIVATE_LIMITED",
    registration_state: "Karnataka",
    incorporation_year: 2003,
    official_domain: "google.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  "amazon": {
    cin: "U74999KA2012PTC063711",
    legal_name: "Amazon Seller Services Private Limited",
    brand_name: "Amazon",
    parent_company: "Amazon.com, Inc. (US)",
    status: "ACTIVE",
    company_type: "PRIVATE_LIMITED",
    registration_state: "Karnataka",
    incorporation_year: 2012,
    official_domain: "amazon.com",
    source: "Local Reference Dataset (public corporate disclosures)",
    source_type: "LOCAL_REFERENCE",
    retrieved_at: LOCAL_REFERENCE_RETRIEVED_AT,
    confidence: 0.98,
  },
  // NOTE: TechCorp Solutions (CIN U72200DL2018PTC123456) was a fabricated test record
  // and has been removed. It was never a verified MCA registry entry.
};

/**
 * Searches local reference dataset for a company name.
 * NOTE: This is NOT a live MCA21 query. Results are from a local reference dataset only.
 * Status returned is LOCAL_REFERENCE_FOUND, not VERIFIED_REGISTERED.
 */
export async function verifyCompanyRegistry(
  companyInput: string,
  claimedCinOrLlpin?: string
): Promise<RegistryLookupResult> {
  const query = companyInput.trim();
  const normalized = normalizeCompanyName(query);
  const evidence: EvidenceItem[] = [];

  if (!query || query.length < 2) {
    return {
      query,
      normalized_query: normalized,
      status: "INSUFFICIENT_DATA",
      evidence: [],
      explanation: "Company name input was too short to perform a registry search.",
    };
  }

  // 1. Direct CIN / LLPIN format validation (format check only — NOT a live lookup)
  if (claimedCinOrLlpin) {
    const cleanId = claimedCinOrLlpin.trim().toUpperCase();
    const isCin = CIN_REGEX.test(cleanId);
    const isLlpin = LLPIN_REGEX.test(cleanId);

    if (isCin || isLlpin) {
      evidence.push({
        id: `EXT-CIN-${crypto.createHash('md5').update(cleanId).digest('hex').substring(0, 6).toUpperCase()}`,
        category: "REGISTRY",
        evidence_type_category: "WEAK_INDICATOR",
        evidence_type: isCin ? "CIN_FORMAT_VALID" : "LLPIN_FORMAT_VALID",
        source_name: "Format Validator (Local)",
        title: `Valid ${isCin ? 'CIN' : 'LLPIN'} Format (Format Check Only — No Live Lookup)`,
        snippet: `Identifier: ${cleanId}`,
        evidence_text: `Registration ID conforms to statutory identifier format rules. NOTE: This is a format check only — no live MCA21 lookup was performed to confirm this identifier exists in the registry.`,
        evidence_strength: "WEAK",
        status: "UNKNOWN",
        severity: "INFO",
        verified: false,
        confidence: 40,
      });
    }
  }

  // 2. Lookup Local Reference Records
  for (const [key, record] of Object.entries(LOCAL_REFERENCE_REGISTRY)) {
    if (normalized.includes(key) || key.includes(normalized)) {
      const isBrandName = record.brand_name && record.brand_name.toLowerCase() !== record.legal_name.toLowerCase();

      evidence.push({
        id: `EXT-MCA21-${crypto.createHash('md5').update(record.legal_name).digest('hex').substring(0, 6).toUpperCase()}`,
        category: "REGISTRY",
        evidence_type_category: "WEAK_INDICATOR",
        evidence_type: "LOCAL_REFERENCE_MATCH",
        source_name: record.source,
        title: `Local Reference Match (MCA21 live query unavailable): ${record.legal_name}`,
        snippet: `CIN: ${record.cin || 'N/A'} · State: ${record.registration_state || 'India'} · Status: ${record.status} (LOCAL REFERENCE ONLY)`,
        evidence_text: `Entity matched local reference dataset. Legal Name: '${record.legal_name}' (Status: ${record.status}, Type: ${record.company_type}). NOTE: This is a local reference record, not a live MCA21 query. Confidence is limited. Do not treat as live statutory verification.`,
        evidence_strength: "MEDIUM",
        status: "UNKNOWN",
        severity: "INFO",
        verified: false,
        confidence: 50,
      });

      return {
        query,
        normalized_query: normalized,
        status: "LOCAL_REFERENCE_FOUND",
        record,
        evidence,
        explanation: `Organization '${record.legal_name}' was found in the local reference dataset. Live MCA21 statutory verification is not available in this environment. Official domain on record: ${record.official_domain || 'N/A'}.`,
        brand_vs_legal_analysis: isBrandName ? {
          is_brand_alias: true,
          claimed_name: query,
          registered_legal_name: record.legal_name,
          parent_entity: record.parent_company,
        } : undefined,
      };
    }
  }

  // 3. Fallback: Not Found in Local Reference (Important: NOT_FOUND != FRAUD)
  evidence.push({
    id: `EXT-MCA21-NF-${crypto.createHash('md5').update(query).digest('hex').substring(0, 6).toUpperCase()}`,
    category: "REGISTRY",
    evidence_type_category: "UNVERIFIED",
    evidence_type: "LOCAL_REFERENCE_NOT_FOUND",
    source_name: "Local Reference Dataset",
    title: "No Local Reference Record Found",
    snippet: `Search for '${query}' returned 0 matches in the local reference dataset.`,
    evidence_text: "Company not found in local reference dataset. Note: 'Not Found' does NOT imply fraudulent activity. The local dataset is limited. The organization may be registered but not in the local list. Live MCA21 verification is not available.",
    evidence_strength: "UNVERIFIED",
    status: "UNKNOWN",
    severity: "INFO",
    verified: false,
    confidence: 30,
  });

  return {
    query,
    normalized_query: normalized,
    status: "NOT_FOUND",
    evidence,
    explanation: `No local reference record was matched for '${query}'. This does NOT mean the company is fraudulent. The local reference dataset is limited. Live MCA21 verification is not available in this environment. Independent verification is recommended.`,
  };
}
