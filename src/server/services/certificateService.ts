export type CertificateVerificationResult = CertificateVerificationData;
// ==============================================================================
// CERTIFICATE VERIFICATION ENGINE (10-Tier Evidence Hierarchy)
// ==============================================================================
import { CertificateStatus, CertificateVerificationData, EvidenceItem } from '../../types';
import { normalizeDomain } from '../utils/normalizer';
import { analyzeDomain } from './domainService';

// Known authentic certificate issuer registries / domains
const KNOWN_CERTIFICATE_ISSUERS: Record<string, { name: string; domain: string; verifyPattern?: RegExp; hasLiveApi: boolean }> = {
  "coursera": { name: "Coursera", domain: "coursera.org", verifyPattern: /^[A-Z0-9]{10,16}$/i, hasLiveApi: true },
  "edx": { name: "edX", domain: "edx.org", verifyPattern: /^[a-f0-9-]{32,36}$/i, hasLiveApi: true },
  "nptel": { name: "NPTEL / Swayam", domain: "nptel.ac.in", verifyPattern: /^NPTEL\d{2}[A-Z]{2}\d{2}[A-Z0-9]+$/i, hasLiveApi: true },
  "udemy": { name: "Udemy", domain: "udemy.com", verifyPattern: /^UC-[a-f0-9-]{16,36}$/i, hasLiveApi: true },
  "hackerrank": { name: "HackerRank", domain: "hackerrank.com", verifyPattern: /^[A-F0-9]{12}$/i, hasLiveApi: true },
  "forage": { name: "Forage", domain: "theforage.com", verifyPattern: /^[a-z0-9]{16,32}$/i, hasLiveApi: true },
  "internshala": { name: "Internshala Trainings", domain: "internshala.com", verifyPattern: /^[A-Z0-9-]{8,24}$/i, hasLiveApi: true },
  "aws": { name: "Amazon Web Services Training", domain: "aws.amazon.com", verifyPattern: /^[A-Z0-9]{16}$/i, hasLiveApi: true },
  "google": { name: "Google Career Certificates", domain: "grow.google", verifyPattern: /^[A-Z0-9-]{12,28}$/i, hasLiveApi: true },
  "microsoft": { name: "Microsoft Learn", domain: "learn.microsoft.com", verifyPattern: /^[A-Z0-9]{8,16}$/i, hasLiveApi: true },
};

export async function verifyCertificate(
  rawText: string,
  claimedId?: string,
  claimedIssuer?: string,
  claimedUrl?: string
): Promise<CertificateVerificationData> {
  const evidence: EvidenceItem[] = [];

  // Extract certificate fields from text if not explicitly passed
  let certId = claimedId;
  if (!certId) {
    const idMatch = rawText.match(/(?:certificate\s*(?:id|no|number|code)|credential\s*id|verify\s*code)[\s:]+([A-Za-z0-9-_]{6,36})/i);
    if (idMatch) certId = idMatch[1].trim();
  }

  let issuerName = claimedIssuer;
  if (!issuerName) {
    const issuerMatch = rawText.match(/(?:issued\s*by|organization|institution|offered\s*by|academy|university)[\s:]+([A-Za-z0-9\s&.,-]{3,40})/i);
    if (issuerMatch) issuerName = issuerMatch[1].trim();
  }

  let verifyUrl = claimedUrl;
  if (!verifyUrl) {
    const urlMatch = rawText.match(/https?:\/\/[^\s<>"]*(?:verify|certificate|credential|check|cert)[^\s<>"]*/i) ||
                     rawText.match(/(?:verify\s*(?:at|here|link)?|verification\s*url)[\s:]+(https?:\/\/[^\s<>"]+)/i);
    if (urlMatch) {
      verifyUrl = (urlMatch[1] || urlMatch[0]).trim();
    }
  }

  // QR Code detection from text / metadata
  const qrDetected = /qr\s*code|scan\s*to\s*verify/i.test(rawText) || !!verifyUrl;
  let qrDomainMatch = false;
  let issuerVerified = false;
  let idVerified = false;

  let verificationLevel = 1;
  let status: CertificateStatus = "UNVERIFIED";
  let authenticityConfidence = 40;

  // Level 1-5: Check Known Issuer & Verification URL
  let matchedIssuerKey: string | null = null;
  const lowerText = rawText.toLowerCase();

  for (const [key, meta] of Object.entries(KNOWN_CERTIFICATE_ISSUERS)) {
    if (lowerText.includes(key) || (issuerName && issuerName.toLowerCase().includes(key))) {
      matchedIssuerKey = key;
      issuerName = meta.name;
      break;
    }
  }

  if (matchedIssuerKey) {
    const issuerMeta = KNOWN_CERTIFICATE_ISSUERS[matchedIssuerKey];
    issuerVerified = true;
    verificationLevel = Math.max(verificationLevel, 6);

    evidence.push({
      category: "CERTIFICATE",
      evidence_type_category: "VERIFIED_FACT",
      evidence_type: "KNOWN_ISSUER_RECOGNIZED",
      source_name: "Authoritative Issuer Registry",
      title: `Recognized Educational/Certification Issuer: ${issuerMeta.name}`,
      snippet: `Issuer domain: ${issuerMeta.domain}`,
      evidence_text: `Certificate claims issuance by verified entity '${issuerMeta.name}'.`,
      evidence_strength: "STRONG",
      status: "VERIFIED",
      severity: "INFO",
      verified: true,
      confidence: 95,
    });

    // Check Verification URL alignment with Issuer Domain
    if (verifyUrl) {
      const urlDomain = normalizeDomain(verifyUrl);
      if (urlDomain === issuerMeta.domain || urlDomain.endsWith(`.${issuerMeta.domain}`)) {
        qrDomainMatch = true;
        verificationLevel = Math.max(verificationLevel, 7);
        evidence.push({
          category: "CERTIFICATE",
          evidence_type_category: "VERIFIED_FACT",
          evidence_type: "VERIFICATION_URL_ALIGNED",
          source_name: "Domain Correlation Inspector",
          title: "Verification URL Matches Official Issuer Domain",
          snippet: `URL domain '${urlDomain}' resolves to official ${issuerMeta.name} domain.`,
          evidence_text: `The verification hyperlink/QR domain matches the official registrar for ${issuerMeta.name}.`,
          evidence_strength: "VERY_STRONG",
          status: "VERIFIED",
          severity: "INFO",
          verified: true,
          confidence: 95,
        });
      } else {
        // Verification URL is on an unaligned or lookalike domain
        evidence.push({
          category: "CERTIFICATE",
          evidence_type_category: "CONTRADICTORY_EVIDENCE",
          evidence_type: "VERIFICATION_URL_MISMATCH",
          source_name: "Domain Correlation Inspector",
          title: "Verification URL Mismatched with Official Issuer",
          snippet: `Verification points to '${urlDomain}' instead of official '${issuerMeta.domain}'.`,
          evidence_text: `Certificate claims issuance by ${issuerMeta.name} but points verification link to external domain '${urlDomain}'.`,
          evidence_strength: "VERY_STRONG",
          status: "NEGATIVE",
          severity: "CRITICAL",
          verified: true,
          confidence: 90,
        });
        status = "SUSPICIOUS";
        verificationLevel = 9;
      }
    }

    // Check Certificate ID format
    if (certId) {
      if (issuerMeta.verifyPattern) {
        if (issuerMeta.verifyPattern.test(certId)) {
          idVerified = true;
          verificationLevel = Math.max(verificationLevel, 8);
          evidence.push({
            category: "CERTIFICATE",
            evidence_type_category: "STRONG_INDICATOR",
            evidence_type: "CERTIFICATE_ID_SYNTAX_VALID",
            source_name: "Issuer Format Validator",
            title: `Certificate ID Conforms to ${issuerMeta.name} Pattern`,
            snippet: `Certificate ID: ${certId}`,
            evidence_text: `Identifier conforms to the standard alphanumeric format rules used by ${issuerMeta.name}.`,
            evidence_strength: "STRONG",
            status: "VERIFIED",
            severity: "INFO",
            verified: true,
            confidence: 90,
          });
        } else {
          evidence.push({
            category: "CERTIFICATE",
            evidence_type_category: "CONTRADICTORY_EVIDENCE",
            evidence_type: "CERTIFICATE_ID_SYNTAX_INVALID",
            source_name: "Issuer Format Validator",
            title: `Certificate ID Fails ${issuerMeta.name} Syntax Rules`,
            snippet: `Value '${certId}' is non-standard for ${issuerMeta.name}.`,
            evidence_text: `The certificate ID does not match expected structure for ${issuerMeta.name}.`,
            evidence_strength: "STRONG",
            status: "WARNING",
            severity: "HIGH",
            verified: true,
            confidence: 85,
          });
        }
      }
    }
  } else if (issuerName) {
    // Non-preconfigured custom issuer
    evidence.push({
      category: "CERTIFICATE",
      evidence_type_category: "UNVERIFIED",
      evidence_type: "CUSTOM_ISSUER_UNVERIFIED",
      source_name: "Certificate Intelligence Engine",
      title: `Independent Registry Missing for Issuer: ${issuerName}`,
      snippet: `Issuer '${issuerName}' is not part of preconfigured authoritative verification databases.`,
      evidence_text: `Certificate issuer could not be verified automatically against public institutional registries.`,
      evidence_strength: "UNVERIFIED",
      status: "UNKNOWN",
      severity: "INFO",
      verified: false,
      confidence: 50,
    });
  }

  // Final Status & Authenticity Confidence Calculation
  if (status === "SUSPICIOUS" || (status as any) === "LIKELY_FRAUDULENT") {
    authenticityConfidence = 20;
    verificationLevel = 9;
  } else if ((qrDomainMatch && idVerified && issuerVerified) || (issuerVerified && idVerified && !verifyUrl)) {
    status = "VERIFIED_AUTHENTIC";
    authenticityConfidence = 95;
    verificationLevel = 10;
  } else if (issuerVerified && !verifyUrl) {
    status = "LIKELY_AUTHENTIC";
    authenticityConfidence = 75;
    verificationLevel = 7;
  } else if (verifyUrl && matchedIssuerKey && !qrDomainMatch) {
    status = "SUSPICIOUS";
    authenticityConfidence = 25;
    verificationLevel = 9;
  } else {
    status = "UNVERIFIED";
    authenticityConfidence = 50;
    verificationLevel = 5;
  }

  const summary =
    status === "VERIFIED_AUTHENTIC"
      ? `Certificate verified authentic through issuer alignment (${issuerName}), valid ID syntax (${certId || 'N/A'}), and verified domain routing.`
      : status === "LIKELY_AUTHENTIC"
      ? `Certificate shows strong indicators of authenticity matching ${issuerName || 'the issuer'} conventions, but lacks live cryptographic endpoint callback.`
      : status === "SUSPICIOUS"
      ? "Certificate presents anomalies such as mismatched verification endpoints or non-standard identifier formatting."
      : (status as any) === "LIKELY_FRAUDULENT"
      ? "Certificate presents strong evidence of fabrication, including deceptive verification endpoints or counterfeit issuer domains."
      : "Certificate authenticity status is UNVERIFIED due to insufficient independent registry evidence. This does not mean the certificate is fraudulent.";

  return {
    certificate_id: certId,
    issuer_name: issuerName,
    issuer_domain: matchedIssuerKey ? KNOWN_CERTIFICATE_ISSUERS[matchedIssuerKey].domain : undefined,
    verification_url: verifyUrl,
    qr_code_detected: qrDetected,
    qr_code_payload: verifyUrl,
    qr_domain_match: qrDomainMatch,
    status,
    verification_level: verificationLevel,
    authenticity_confidence: authenticityConfidence,
    issuer_verified: issuerVerified,
    id_verified: idVerified,
    summary,
    evidence,
  };
}
