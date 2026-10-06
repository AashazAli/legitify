// ==============================================================================
// LEGITIFY LEGITIMATE PATTERN & COUNTER-EVIDENCE ENGINE
// Version: LEGITIFY-LP-v2.0
// Actively evaluates positive recruitment indicators and evaluates counter-evidence
// to prevent false positives for startups and legitimate staffing agencies.
// ==============================================================================

import { LegitimatePatternMatch, CounterEvidenceMatch } from '../../types/forensicTypes';
import { EvidenceItem } from '../../types';

export interface LegitimacyEvaluationInputs {
  isCorporateDomainAligned: boolean;
  hasValidMx: boolean;
  hasCareersPageMatch: boolean;
  hasZeroFeeCompliance: boolean;
  isStatutoryRegistered: boolean;
  cinNumber?: string;
  hasInternalCoherence: boolean;
  isRecognizedStaffingAgency: boolean;
  isYoungStartup: boolean;
  evidenceList: EvidenceItem[];
  companyName?: string;
  domain?: string;
  recruiterEmail?: string;
}

const RECOGNIZED_STAFFING_AGENCIES = [
  'randstad', 'teamlease', 'quess', 'adecco', 'manpower', 'michael page',
  'kelly services', 'allegis', 'robert half', 'ciiel', 'abc consultants',
  'careernet', 'naukri', 'foundit', 'monster'
];

/**
 * Checks whether an entity or recruiter represents a recognized staffing partner.
 */
export function isRecognizedStaffingPartner(text: string): boolean {
  if (!text) return false;
  const lower = text.toLowerCase();
  return RECOGNIZED_STAFFING_AGENCIES.some(agency => lower.includes(agency));
}

/**
 * Evaluates legitimate recruitment patterns and counter-evidence.
 */
export function evaluateLegitimacyPatterns(inputs: LegitimacyEvaluationInputs): {
  patterns: LegitimatePatternMatch[];
  counterEvidence: CounterEvidenceMatch[];
} {
  const patterns: LegitimatePatternMatch[] = [];
  const counterEvidence: CounterEvidenceMatch[] = [];

  // Helper to extract evidence IDs
  const findEvidenceIds = (category: string): string[] => {
    return inputs.evidenceList
      .filter(e => e.category === category)
      .map(e => (e as any).evidence_id || (e as any).id || 'E-LEG')
      .slice(0, 3);
  };

  // ----------------------------------------------------------------------------
  // LP001: Official Corporate Domain & Mail Alignment
  // ----------------------------------------------------------------------------
  if (inputs.isCorporateDomainAligned && inputs.hasValidMx) {
    patterns.push({
      patternId: 'LP001',
      name: 'Official Corporate Domain & Mail Alignment',
      description: 'Recruiter communicates from an authenticated corporate email domain strictly aligned with the company.',
      strength: 'STRONG',
      confidence: 92,
      matchedSignals: [
        'Recruiter email domain directly matches company primary domain',
        'Authoritative MX mail exchange records active and verified',
      ],
      evidenceIds: findEvidenceIds('EMAIL'),
      explanation: 'Authentic corporate email infrastructure with verified mail exchange records provides cryptographic and routing proof of domain alignment.',
    });
  }

  // ----------------------------------------------------------------------------
  // LP002: Public Career Portal Corroboration
  // ----------------------------------------------------------------------------
  if (inputs.hasCareersPageMatch) {
    patterns.push({
      patternId: 'LP002',
      name: 'Public Career Portal Corroboration',
      description: 'The target role, internship program, or recruitment channel is verified on the official corporate careers portal.',
      strength: 'STRONG',
      confidence: 90,
      matchedSignals: [
        'Verified corporate career portal found on official domain',
        'Official recruitment channel confirmed',
      ],
      evidenceIds: findEvidenceIds('COMPANY'),
      explanation: 'Public job listings hosted directly on the official corporate domain confirm active, legitimate hiring activity.',
    });
  }

  // ----------------------------------------------------------------------------
  // LP003: Zero-Fee Employment Standard
  // ----------------------------------------------------------------------------
  if (inputs.hasZeroFeeCompliance) {
    patterns.push({
      patternId: 'LP003',
      name: 'Zero-Fee Employment Standard',
      description: 'Document demonstrates full compliance with corporate zero-fee recruitment standards (no candidate fees or security deposits).',
      strength: 'STRONG',
      confidence: 95,
      matchedSignals: [
        'No candidate payment, application fee, or security deposit requested',
        'Standard commercial compensation structure with zero candidate liabilities',
      ],
      evidenceIds: findEvidenceIds('DOCUMENT'),
      explanation: 'Genuine employment relationships always maintain a strictly one-way financial flow: employer pays employee.',
    });
  }

  // ----------------------------------------------------------------------------
  // LP004: Statutory Corporate Registration
  // ----------------------------------------------------------------------------
  if (inputs.isStatutoryRegistered) {
    patterns.push({
      patternId: 'LP004',
      name: 'Statutory Corporate Transparency',
      description: 'Target enterprise is documented in formal corporate registry records with registered office and valid corporate identity.',
      strength: 'MODERATE',
      confidence: 85,
      matchedSignals: [
        inputs.cinNumber ? `Valid CIN / Registration Identifier: ${inputs.cinNumber}` : 'Entity documented in corporate reference dataset',
        'Formal corporate entity identified',
      ],
      evidenceIds: findEvidenceIds('REGISTRY'),
      explanation: 'Verified corporate registration confirms that the employer is a legally incorporated commercial entity.',
    });
  }

  // ----------------------------------------------------------------------------
  // LP005: Internal Document & Temporal Coherence
  // ----------------------------------------------------------------------------
  if (inputs.hasInternalCoherence) {
    patterns.push({
      patternId: 'LP005',
      name: 'Internal Document & Temporal Coherence',
      description: 'All internal document terms, compensation structures, dates, and signatory details are chronologically and logically consistent.',
      strength: 'MODERATE',
      confidence: 80,
      matchedSignals: [
        'Consistent role, duration, and reporting dates',
        'Internal terms exhibit standard formal enterprise drafting standards',
      ],
      evidenceIds: findEvidenceIds('DOCUMENT'),
      explanation: 'Absence of conflicting figures, typos, or chronological errors supports genuine formal drafting.',
    });
  }

  // ----------------------------------------------------------------------------
  // COUNTER-EVIDENCE EVALUATION (False-Positive Controls)
  // ----------------------------------------------------------------------------
  // 1. Recognized Staffing Agency Counter-Check
  const combinedContext = `${inputs.companyName || ''} ${inputs.recruiterEmail || ''} ${inputs.domain || ''}`;
  if (isRecognizedStaffingPartner(combinedContext)) {
    counterEvidence.push({
      signalId: 'COUNTER-STAFFING-AGENCY',
      originalRiskSignal: 'Recruiter domain differs from claimed company domain',
      counterEvidence: 'Recruiter is associated with a recognized, accredited third-party staffing/recruiting firm.',
      source: 'Global Staffing Partner Index',
      authorityTier: 'TIER_2',
      mitigationEffect: 'Downgrades DOMAIN_MISMATCH penalty when authorized third-party agency status is verified.',
    });
  }

  // 2. Young Startup / Early-Stage Venture Counter-Check
  if (inputs.isYoungStartup && inputs.hasZeroFeeCompliance) {
    counterEvidence.push({
      signalId: 'COUNTER-EARLY-STAGE-STARTUP',
      originalRiskSignal: 'Domain is newly registered (< 1 year old) or company registry lookup is pending',
      counterEvidence: 'Entity exhibits normal early-stage startup profile with zero fee demands and transparent founder contacts.',
      source: 'Early-Stage Corporate Transparency Filter',
      authorityTier: 'TIER_2',
      mitigationEffect: 'Prevents automatic scam escalation for young companies without established historical domain age.',
    });
  }

  return { patterns, counterEvidence };
}
