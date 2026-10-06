// ==============================================================================
// LEGITIFY ML FEATURE EXTRACTOR
// Transforms multi-source evidence into a standardized numerical feature vector
// ==============================================================================
import { CompanyData } from '../services/companyService';
import { DomainData } from '../services/domainService';
import { RecruiterData } from '../services/emailService';
import { DocumentExtractionResult } from '../services/documentService';
import { CertificateVerificationData } from '../../types';
import { ThreatData } from '../services/threatService';

export interface MLFeatureVector {
  // Company Features
  company_registered: number; // 1 or 0
  company_active: number; // 1 or 0
  
  // Domain Features
  domain_age_days: number; // raw days normalized
  domain_lookalike: number; // 1 if lookalike, 0 otherwise
  domain_ssl_valid: number; // 1 or 0
  domain_has_mx: number; // 1 or 0

  // Recruiter / Email Features
  email_free_provider: number; // 1 if @gmail.com/@yahoo.com, 0 if custom domain
  email_domain_match: number; // 1 if matches company domain, 0 if mismatched

  // Offer / Document Features
  fee_demand_detected: number; // 1 if fee/deposit/training requested, 0 otherwise
  payment_handle_present: number; // 1 if UPI/wallet/crypto detected, 0 otherwise
  urgency_signals: number; // 1 if urgent/threatening terms present, 0 otherwise

  // Certificate Features
  cert_verified_authentic: number; // 1 if verified authentic, 0 otherwise
  cert_unverified: number; // 1 if unverified, 0 otherwise
  cert_suspicious_url: number; // 1 if URL mismatched/suspicious, 0 otherwise

  // Threat Features
  threat_iocs_matched: number; // count of matched blacklisted IOCs
}

export function extractMLFeatures(ctx: {
  companyData?: CompanyData;
  domainData?: DomainData;
  recruiterData?: RecruiterData;
  documentData?: DocumentExtractionResult;
  certificateData?: CertificateVerificationData;
  threatData?: ThreatData;
}): { vector: MLFeatureVector; normalizedVector: number[] } {
  const { companyData, domainData, recruiterData, documentData, certificateData, threatData } = ctx;

  const vector: MLFeatureVector = {
    company_registered: companyData?.status === 'ACTIVE' || (companyData?.registry_status as string) === 'VERIFIED_INDEPENDENTLY' || (companyData?.registry_status as string) === 'LOCAL_REFERENCE_FOUND' ? 1 : 0,
    company_active: companyData?.status === 'ACTIVE' ? 1 : 0,
    domain_age_days: domainData?.age_days ? Math.min(domainData.age_days, 1825) / 1825 : 0, // normalized up to 5 years
    domain_lookalike: domainData?.lookalike_detected ? 1 : 0,
    domain_ssl_valid: domainData?.ssl_valid ? 1 : 0,
    domain_has_mx: domainData?.has_dns ? 1 : 0,
    email_free_provider: recruiterData?.is_free_provider ? 1 : 0,
    email_domain_match: (recruiterData?.domain_alignment as string) === 'MATCH' || (recruiterData?.domain_alignment as string) === 'EXACT_MATCH' ? 1 : 0,
    fee_demand_detected: documentData?.has_fee_demand ? 1 : 0,
    payment_handle_present: (documentData?.requested_fees?.length ?? 0) > 0 ? 1 : 0,
    urgency_signals: /immediate|urgent|within\s*24\s*hours|mandatory\s*before|cancel\s*offer/i.test(documentData?.extracted_text || '') ? 1 : 0,
    cert_verified_authentic: certificateData?.status === 'VERIFIED_AUTHENTIC' ? 1 : 0,
    cert_unverified: certificateData?.status === 'UNVERIFIED' ? 1 : 0,
    cert_suspicious_url: certificateData?.status === 'SUSPICIOUS' || (certificateData?.status as any) === 'LIKELY_FRAUDULENT' ? 1 : 0,
    threat_iocs_matched: threatData?.indicators?.length ?? 0,
  };

  const normalizedVector = [
    vector.company_registered,
    vector.company_active,
    vector.domain_age_days,
    vector.domain_lookalike,
    vector.domain_ssl_valid,
    vector.domain_has_mx,
    vector.email_free_provider,
    vector.email_domain_match,
    vector.fee_demand_detected,
    vector.payment_handle_present,
    vector.urgency_signals,
    vector.cert_verified_authentic,
    vector.cert_unverified,
    vector.cert_suspicious_url,
    Math.min(vector.threat_iocs_matched, 5) / 5,
  ];

  return { vector, normalizedVector };
}
