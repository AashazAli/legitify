// ==============================================================================
// COMPANY INTELLIGENCE & REGISTRY SERVICE
// ==============================================================================
import { supabaseAdmin } from '../../lib/supabase/server';
import { normalizeCompanyName, normalizeDomain } from '../utils/normalizer';
import { EvidenceItem } from '../../types';

export interface CompanyData {
  id?: string;
  normalized_name: string;
  legal_name: string;
  registration_number?: string;
  status?: "ACTIVE" | "INACTIVE" | "DISSOLVED" | "UNKNOWN";
  registry_status: "VERIFIED" | "UNVERIFIED" | "NOT_FOUND" | "NOT_INDEPENDENTLY_VERIFIED" | "SOURCE_UNAVAILABLE";
  registered_address?: string;
  country: string;
  state?: string;
  city?: string;
  website?: string;
  domain?: string;
  trust_score?: number;
  last_verified_at?: string;
  is_cached?: boolean;
}

// CIN pattern for Indian companies: [U/L][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}
const CIN_REGEX = /^[UL][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$/i;
// GST pattern: [0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}
const GST_REGEX = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/i;

// Dynamic Corporate Entity Intelligence (Zero hardcoded static company authorities)
export async function lookupCompany(
  companyInput: string,
  claimedDomain?: string,
  claimedCin?: string
): Promise<{ data: CompanyData; evidence: EvidenceItem[]; score_modifier: number }> {
  const normalized = normalizeCompanyName(companyInput);
  const evidence: EvidenceItem[] = [];
  let score_modifier = 0;

  let company: CompanyData = {
    normalized_name: normalized,
    legal_name: companyInput.trim(),
    country: "India",
    status: "ACTIVE",
    registry_status: "NOT_INDEPENDENTLY_VERIFIED",
  };

  if (!normalized) {
    return { data: company, evidence, score_modifier };
  }

  // 2. Check Shared Intelligence Database Cache
  try {
    const { data: cached } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('normalized_name', normalized)
      .maybeSingle();

    if (cached) {
      company = {
        id: cached.id,
        normalized_name: cached.normalized_name,
        legal_name: cached.legal_name || companyInput,
        registration_number: cached.registration_number,
        registry_status: cached.registry_status,
        registered_address: cached.registered_address,
        country: cached.country || "India",
        state: cached.state,
        city: cached.city,
        website: cached.website,
        domain: cached.domain,
        trust_score: cached.trust_score,
        last_verified_at: cached.last_verified_at,
        is_cached: true,
      };

      evidence.push({
        category: "COMPANY",
        evidence_type: "SHARED_INTELLIGENCE_CACHE",
        source_name: "Legitify Historical Intelligence Cache",
        title: `Reused Shared Intelligence for ${company.legal_name}`,
        snippet: `Verified registry status: ${company.registry_status} · Last updated: ${company.last_verified_at || 'Recent'}`,
        evidence_text: `System matched normalized entity '${normalized}' in shared corporate intelligence directory.`,
        evidence_strength: "STRONG",
        status: company.registry_status === "VERIFIED" ? "VERIFIED" : "WARNING",
        severity: "INFO",
        verified: company.registry_status === "VERIFIED",
        confidence: 90.0,
      });

      if (company.registry_status === "VERIFIED") score_modifier += 25;
      return { data: company, evidence, score_modifier };
    }
  } catch {
    // Database cache check skipped
  }

  // 3. Validate Provided Identification Numbers (CIN / GST)
  if (claimedCin) {
    const isCin = CIN_REGEX.test(claimedCin.trim());
    if (isCin) {
      company.registration_number = claimedCin.trim().toUpperCase();
      evidence.push({
        category: "REGISTRY",
        evidence_type: "CIN_FORMAT_VALID",
        source_name: "Ministry of Corporate Affairs (MCA) Format Validator",
        title: "Valid MCA Corporate Identification Number (CIN) Format",
        snippet: `CIN: ${claimedCin.trim().toUpperCase()}`,
        evidence_text: "Corporate identification number conforms to statutory format rules for registered Indian corporate entities.",
        evidence_strength: "MEDIUM",
        status: "VERIFIED",
        severity: "INFO",
        verified: false,
        confidence: 80.0,
      });
      score_modifier += 15;
    } else {
      evidence.push({
        category: "REGISTRY",
        evidence_type: "CIN_FORMAT_INVALID",
        source_name: "Ministry of Corporate Affairs (MCA) Format Validator",
        title: "Invalid CIN / Registration Format",
        snippet: `Submitted value '${claimedCin}' fails statutory 21-character CIN syntax rules.`,
        evidence_text: "Claimed corporate identification number does not conform to valid registration formatting.",
        evidence_strength: "STRONG",
        status: "WARNING",
        severity: "HIGH",
        verified: true,
        confidence: 95.0,
      });
      score_modifier -= 20;
    }
  }

  // 4. Independent Public Registry Statement
  evidence.push({
    category: "REGISTRY",
    evidence_type: "INDEPENDENT_REGISTRY_STATUS",
    source_name: "Corporate Registry Adapter",
    title: "Independent Registry Lookup: Not Independently Verified",
    snippet: "Official live registry API access is not configured. Company registration could not be verified automatically.",
    evidence_text: "Legitify did not fabricate or simulate government verification. Further independent verification is recommended.",
    evidence_strength: "UNVERIFIED",
    status: "UNKNOWN",
    severity: "INFO",
    verified: false,
    confidence: 60.0,
  });

  return { data: company, evidence, score_modifier };
}
