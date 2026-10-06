// ==============================================================================
// LEGITIFY FRAUD PATTERN LIBRARY & DETECTION ENGINE
// Version: LEGITIFY-FP-v2.0
// Detects multi-signal fraud pattern clusters with versioned, testable logic
// ==============================================================================

import { FraudPatternMatch } from '../../types/forensicTypes';
import { EvidenceItem } from '../../types';

export interface FraudPatternEvaluationInputs {
  hasPaymentDemand: boolean;
  paymentAmount?: string;
  paymentMethods?: string[];
  isInternship: boolean;
  isEmploymentPromise: boolean;
  isRegisteredCompanyClaimed: boolean;
  isLookalikeDomain: boolean;
  isFreeWebmail: boolean;
  isRecruiterUnverified: boolean;
  hasTrainingFee: boolean;
  hasUrgentDeadline: boolean;
  requestsSensitiveCredentials: boolean;
  suspiciousUrlPresent: boolean;
  offPlatformMigration: boolean;
  evidenceList: EvidenceItem[];
}

/**
 * Evaluates multi-signal fraud patterns.
 * Correlation > Counting: Detects explicit toxic combinations.
 */
export function evaluateFraudPatterns(inputs: FraudPatternEvaluationInputs): FraudPatternMatch[] {
  const matches: FraudPatternMatch[] = [];

  // Helper to extract evidence IDs matching criteria
  const findEvidenceIds = (category?: string, typeSubstr?: string): string[] => {
    return inputs.evidenceList
      .filter(e => {
        const catMatch = !category || e.category === category;
        const typeMatch = !typeSubstr || (e.evidence_type && e.evidence_type.includes(typeSubstr));
        return catMatch && typeMatch;
      })
      .map(e => (e as any).evidence_id || (e as any).id || 'E-GEN')
      .slice(0, 5);
  };

  // ----------------------------------------------------------------------------
  // FP001: Recruitment Payment Scam
  // Rule: (has_payment_demand) AND (employment_promise OR internship_offer)
  // ----------------------------------------------------------------------------
  if (inputs.hasPaymentDemand && (inputs.isEmploymentPromise || inputs.isInternship)) {
    const paymentEvIds = findEvidenceIds('DOCUMENT', 'PAYMENT');
    matches.push({
      patternId: 'FP001',
      name: 'Recruitment Payment Scam',
      description: 'Candidate is required to transfer money, security deposits, or registration charges as a condition of employment or internship.',
      severity: 'CRITICAL',
      confidence: 98,
      matchedSignals: [
        'Candidate payment / deposit requested in document',
        inputs.paymentAmount ? `Explicit payment amount specified: ${inputs.paymentAmount}` : 'Upfront fee condition',
        'Official employment / internship position promised',
      ],
      evidenceIds: paymentEvIds.length > 0 ? paymentEvIds : ['E-PAY-DEMAND'],
      explanation: 'Legitimate employers and corporate internship sponsors NEVER charge candidates application fees, laptop deposits, or onboarding charges. This is the #1 signature of fraudulent recruitment schemes.',
    });
  }

  // ----------------------------------------------------------------------------
  // FP002: Corporate Impersonation
  // Rule: (registered_company_claimed) AND (lookalike_domain OR free_webmail) AND (unverified_recruiter)
  // ----------------------------------------------------------------------------
  if (inputs.isRegisteredCompanyClaimed && (inputs.isLookalikeDomain || inputs.isFreeWebmail) && inputs.isRecruiterUnverified) {
    const domainEvIds = findEvidenceIds('DOMAIN', 'LOOKALIKE');
    const emailEvIds = findEvidenceIds('EMAIL');
    matches.push({
      patternId: 'FP002',
      name: 'Corporate Impersonation',
      description: 'Perpetrators claim the legal identity of an established organization while using lookalike domains or generic webmail to conduct unverified recruitment.',
      severity: 'CRITICAL',
      confidence: 94,
      matchedSignals: [
        'Claimed identity of established corporate enterprise',
        inputs.isLookalikeDomain ? 'Suspected brand typosquatting / lookalike domain' : 'Enterprise recruitment conducted via public webmail (@gmail/@yahoo)',
        'Recruiter identity unverified on official corporate roster',
      ],
      evidenceIds: [...domainEvIds, ...emailEvIds].slice(0, 5),
      explanation: 'Established organizations own and strictly enforce communication through their verified primary domains. Discrepancies between the company name and recruiter domain indicate corporate identity spoofing.',
    });
  }

  // ----------------------------------------------------------------------------
  // FP003: Fake Internship Pattern
  // Rule: (internship_claim) AND (training_fee OR payment) AND (certificate_promise)
  // ----------------------------------------------------------------------------
  if (inputs.isInternship && (inputs.hasPaymentDemand || inputs.hasTrainingFee)) {
    matches.push({
      patternId: 'FP003',
      name: 'Fake Internship Pattern',
      description: 'Internship offer conditioned on paid training, certification fees, or software kit deposits.',
      severity: 'CRITICAL',
      confidence: 92,
      matchedSignals: [
        'Internship opportunity promised to student/applicant',
        'Mandatory fee demanded for training, registration, or kit deposit',
      ],
      evidenceIds: findEvidenceIds('DOCUMENT', 'PAYMENT'),
      explanation: 'Predatory internship schemes monetize students by demanding upfront training or registration fees under the guise of an internship.',
    });
  }

  // ----------------------------------------------------------------------------
  // FP004: Task / Training Scam
  // Rule: (has_training_fee) AND (urgent_deadline)
  // ----------------------------------------------------------------------------
  if (inputs.hasTrainingFee && inputs.hasUrgentDeadline) {
    matches.push({
      patternId: 'FP004',
      name: 'Task / Training Scam',
      description: 'Job offer requires upfront paid training material or assessment fees with artificial short-fuse urgency.',
      severity: 'HIGH',
      confidence: 88,
      matchedSignals: [
        'Training fee or assessment fee required',
        'Artificial urgency or immediate payment deadline enforced',
      ],
      evidenceIds: findEvidenceIds('DOCUMENT'),
      explanation: 'Scammers frequently manufacture artificial deadlines (e.g. "Pay within 24 hours to secure your slot") to induce panicked compliance before candidates can verify the company.',
    });
  }

  // ----------------------------------------------------------------------------
  // FP005: Credential Harvesting
  // Rule: (requests_sensitive_credentials OR suspicious_url)
  // ----------------------------------------------------------------------------
  if (inputs.requestsSensitiveCredentials || inputs.suspiciousUrlPresent) {
    matches.push({
      patternId: 'FP005',
      name: 'Credential Harvesting',
      description: 'Offer letter solicits sensitive credentials, banking access, or directs candidate to unverified data collection portals.',
      severity: 'CRITICAL',
      confidence: 90,
      matchedSignals: [
        inputs.requestsSensitiveCredentials ? 'Requests sensitive financial credentials or passwords' : 'Directs candidate to suspicious URL',
      ],
      evidenceIds: findEvidenceIds('THREAT'),
      explanation: 'Legitimate HR onboarding collects identity proofs only after contract execution through secured, authenticated corporate HRIS systems, never via unencrypted forms or third-party links.',
    });
  }

  // ----------------------------------------------------------------------------
  // FP006: Off-Platform Recruitment Migration
  // Rule: (off_platform_migration) AND (is_registered_company_claimed)
  // ----------------------------------------------------------------------------
  if (inputs.offPlatformMigration && inputs.isRegisteredCompanyClaimed) {
    matches.push({
      patternId: 'FP006',
      name: 'Off-Platform Recruitment Migration',
      description: 'Corporate hiring conversation is steered to Telegram, WhatsApp, or personal messaging channels.',
      severity: 'HIGH',
      confidence: 85,
      matchedSignals: [
        'Recruiter directs candidate to unmonitored messaging app (Telegram/WhatsApp)',
        'Formal corporate ATS or corporate email channel bypassed',
      ],
      evidenceIds: findEvidenceIds('EMAIL'),
      explanation: 'Migrating candidates away from formal enterprise email to end-to-end encrypted personal messaging channels shields fraudulent operators from enterprise security monitoring.',
    });
  }

  return matches;
}
