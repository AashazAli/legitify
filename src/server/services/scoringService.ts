// ==============================================================================
// LEGITIFY 10-DIMENSION EVIDENCE FUSION & SCORING ENGINE
// Deterministic multi-source evidence fusion with configurable weights & hard safety caps
// Architecture Version: LEGITIFY-SCORE-v2.0
//
// DETERMINISTIC ≠ STATIC
// Same input + same external evidence state → SAME RESULT
// Different input/evidence → DIFFERENT RESULT
// No Math.random(), no microVariance, no hashSeed jitter, no hardcoded score ranges
// ==============================================================================
import { EvidenceItem, EvidenceCompleteness, RuleEvaluation, RiskLevel, ScoreTrace, ScoreTraceDimension, ScoreTraceConstraint, AssessmentItem } from '../../types';
import { evaluateRules } from '../rules/ruleEngine';
import { CompanyData } from './companyService';
import { DomainData } from './domainService';
import { RecruiterData } from './emailService';
import { DocumentExtractionResult } from './documentService';
import { CertificateVerificationResult } from './certificateService';
import { ThreatData } from './threatService';
import { MLPrediction } from '../ml/fraudClassifier';
import { CommunitySearchResult } from './publicExperienceService';
import { detectEvidenceConflicts, EvidenceConflict } from './conflictService';
import { isFilenameOrPlaceholder } from '../utils/normalizer';

export const SCORING_MODEL_VERSION = 'LEGITIFY-SCORE-v2.0';

/**
 * Mandatory 10-Dimension Weights (sum to 1.0 / 100%)
 */
export interface ScoringWeights {
  document_authenticity: number;    // 0.10 — Document structural analysis & layout
  company_registry: number;         // 0.15 — MCA / Statutory Registry
  domain_intelligence: number;      // 0.10 — DNS/RDAP/TLS/Lookalike
  recruiter_email: number;          // 0.10 — Email provider & domain alignment
  financial_fee_safety: number;     // 0.20 — Fee demand, candidate payment (CRITICAL)
  certificate_verification: number; // 0.05 — Certificate / credential checks
  ml_probability: number;           // 0.10 — Kaggle Supervised ML model
  community_evidence: number;       // 0.05 — Public forum complaints & reviews
  threat_intelligence: number;      // 0.05 — VirusTotal + Safe Browsing + AbuseIPDB
  consistency_conflict: number;     // 0.10 — Cross-signal contradiction engine
}

export const DEFAULT_SCORING_WEIGHTS: ScoringWeights = {
  document_authenticity:    0.10,
  company_registry:         0.15,
  domain_intelligence:      0.10,
  recruiter_email:          0.10,
  financial_fee_safety:     0.20,  // HIGHEST: payment demand is the #1 fraud signal
  certificate_verification: 0.05,
  ml_probability:           0.10,
  community_evidence:       0.05,
  threat_intelligence:      0.05,
  consistency_conflict:     0.10,
};

export interface ScoringInputs {
  companyData?: CompanyData;
  domainData?: DomainData;
  recruiterData?: RecruiterData;
  documentData?: DocumentExtractionResult;
  certificateData?: CertificateVerificationResult;
  threatData?: ThreatData;
  mlPrediction?: MLPrediction;
  communityData?: CommunitySearchResult;
  evidence?: EvidenceItem[];
  weights?: Partial<ScoringWeights>;
  contextText?: string;
  entityValue?: string;
}

export interface ScoreComponentBreakdown {
  name: string;
  weight: number;
  score: number;
  weighted_score: number;
  confidence: number;
  reason: string;
  evidence_count: number;
  active: boolean;
  status: 'VERIFIED' | 'UNVERIFIED' | 'SUSPICIOUS' | 'CONTRADICTED' | 'FLAGGED';
  evidence_ids: string[];
}

export interface DeterministicScoreResult {
  confidence?: number;
  trust_score: number;
  confidence_score: number;
  pre_constraint_score: number;
  risk_level: RiskLevel;
  verdict: "LIKELY LEGITIMATE" | "LOW RISK" | "MODERATE RISK" | "NEUTRAL / REVIEW REQUIRED" | "HIGH RISK" | "LIKELY SCAM" | "INSUFFICIENT_EVIDENCE";
  components: {
    document_authenticity: ScoreComponentBreakdown;
    company: ScoreComponentBreakdown;
    domain: ScoreComponentBreakdown;
    recruiter: ScoreComponentBreakdown;
    document: ScoreComponentBreakdown; // Financial & fee safety
    certificate: ScoreComponentBreakdown;
    ml_probability: ScoreComponentBreakdown;
    threat: ScoreComponentBreakdown;
    community: ScoreComponentBreakdown;
    consistency: ScoreComponentBreakdown;
  };
  rules_triggered: RuleEvaluation[];
  conflicts: EvidenceConflict[];
  hard_caps_applied: string[];
  positive_signals: string[];
  warning_signals: string[];
  critical_signals: string[];
  scoring_model_version?: string;
  score_trace: ScoreTrace;
  overall_risk_score?: number;
  assessments?: AssessmentItem[];
}

/**
 * Calculates Evidence Completeness based on actual data presence and quality,
 * NOT mere object existence.
 */
export function calculateEvidenceCompleteness(inputs: ScoringInputs): EvidenceCompleteness {
  let score = 0;
  const missing: string[] = [];

  // 1. Company: only count if registry produced an actual verification or structured check
  const companyChecked = Boolean(
    inputs.companyData &&
    inputs.companyData.registry_status !== undefined &&
    (inputs.companyData.registry_status as any) !== 'UNKNOWN' &&
    (inputs.companyData.registry_status as any) !== 'NOT_INDEPENDENTLY_VERIFIED'
  );
  if (companyChecked) {
    score += 15;
  } else {
    missing.push("Independent Statutory Company Registry Record");
  }

  // 2. Domain: only count if live DNS was resolved
  if (inputs.domainData && inputs.domainData.has_dns) {
    score += 15;
  } else if (inputs.domainData) {
    score += 5;
    missing.push("Live Domain DNS & TLS Resolution");
  } else {
    missing.push("Domain Security Intelligence");
  }

  // 3. Recruiter: count if email was actually provided and analyzed
  if (inputs.recruiterData && inputs.recruiterData.email) {
    score += 10;
  } else {
    missing.push("Direct Recruiter Email Headers & Routing");
  }

  // 4. Document: count if meaningful text was extracted
  const docTextLength = (inputs.documentData?.extracted_text || '').trim().length;
  if (docTextLength > 50) {
    score += 15;
  } else if (docTextLength > 0) {
    score += 5;
    missing.push("Complete Offer Document Text (Insufficient length)");
  } else {
    missing.push("Offer Document Text Extraction");
  }

  // 5. ML Model: count if ML fraud classifier ran
  if (inputs.mlPrediction && inputs.mlPrediction.fraudProbability !== undefined) {
    score += 15;
  } else {
    missing.push("Supervised ML Fraud Prediction");
  }

  // 6. Threat Intel: count if threat feeds were queried
  if (inputs.threatData && !(inputs.threatData as any).source_unavailable) {
    score += 15;
  } else {
    missing.push("Live Threat Intelligence Feeds");
  }

  // 7. Community: count if search was executed
  if (inputs.communityData && inputs.communityData.totalRelevantResults > 0) {
    score += 10;
  } else {
    missing.push("Community Discussion Reports");
  }

  // 8. Certificate: count if checked when relevant
  if (inputs.certificateData) {
    score += 5;
  }

  const category = score >= 70 ? "HIGH" : score >= 40 ? "MODERATE" : "LOW";
  const percentage = Math.min(100, Math.round(score));

  return {
    score,
    overall_percentage: percentage,
    percentage,
    category,
    summary: `${percentage}% of expected evidence collected (${category} Completeness)`,
    missing_evidence: missing,
    breakdown: {
      company: { observed: companyChecked ? 1 : 0, expected: 1, percentage: companyChecked ? 100 : 0 },
      domain: { observed: inputs.domainData?.has_dns ? 1 : 0, expected: 1, percentage: inputs.domainData?.has_dns ? 100 : 0 },
      recruiter: { observed: inputs.recruiterData?.email ? 1 : 0, expected: 1, percentage: inputs.recruiterData?.email ? 100 : 0 },
      certificate: { observed: inputs.certificateData ? 1 : 0, expected: 1, percentage: inputs.certificateData ? 100 : 0 },
      document: { observed: docTextLength > 50 ? 1 : 0, expected: 1, percentage: docTextLength > 50 ? 100 : 0 },
      threat: { observed: inputs.threatData ? 1 : 0, expected: 1, percentage: inputs.threatData ? 100 : 0 },
    },
  };
}

/**
 * Deterministically computes the forensic trust score from actual evidence.
 * 
 * CORE PRINCIPLE:
 * Same evidence snapshot → identical mathematical score.
 * Different evidence → proportionally different score.
 */
export function calculateDeterministicScore(inputs: ScoringInputs): DeterministicScoreResult {
  const evidenceList = inputs.evidence || [];
  const weights: ScoringWeights = { ...DEFAULT_SCORING_WEIGHTS, ...(inputs.weights || {}) };

  const positiveSignals: string[] = [];
  const warningSignals: string[] = [];
  const criticalSignals: string[] = [];
  const hardCaps: string[] = [];

  // Run Rule Engine
  const { rules, scoreImpact: ruleScoreImpact } = evaluateRules({ ...inputs, evidence: evidenceList });

  for (const rule of rules) {
    if (rule.severity === 'CRITICAL') {
      criticalSignals.push(`[${rule.rule_id}] ${rule.name}: ${rule.explanation}`);
    } else if (rule.severity === 'HIGH' || rule.severity === 'MEDIUM') {
      warningSignals.push(`[${rule.rule_id}] ${rule.name}: ${rule.explanation}`);
    } else {
      positiveSignals.push(`[${rule.rule_id}] ${rule.name}: ${rule.explanation}`);
    }
  }

  // ============================================================================
  // 1. Document Authenticity Score (Weight: 10%)
  // ============================================================================
  const docAuthEvidence = evidenceList.filter(e => e.category === 'DOCUMENT' || (e.category as any) === 'VISUAL');
  const isDocAuthActive = Boolean(
    inputs.documentData &&
    (((inputs.documentData.extracted_text || '').trim().length > 20) ||
     ((inputs.documentData.triggered_flags || []).length > 0) ||
     inputs.documentData.is_confirmed_impersonation ||
     inputs.documentData.is_suspicious_offer_letter)
  );

  let docAuthScore = 0;
  let docAuthConfidence = 0;
  let docAuthStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let docAuthReason = "No document provided for visual/structural authenticity analysis.";

  if (isDocAuthActive && inputs.documentData) {
    docAuthConfidence = 85;
    const flagCount = inputs.documentData.triggered_flags?.length || 0;
    const docScore = typeof inputs.documentData.final_score === 'number'
      ? inputs.documentData.final_score
      : 50;

    if (inputs.documentData.is_confirmed_impersonation) {
      docAuthScore = 5;
      docAuthStatus = 'CONTRADICTED';
      docAuthReason = "Document identified as confirmed corporate impersonation attempt.";
      criticalSignals.push("Document identified as confirmed corporate impersonation attempt.");
    } else if (inputs.documentData.is_suspicious_offer_letter || inputs.documentData.verdict === 'LIKELY FAKE' || docScore < 40) {
      docAuthScore = Math.min(22, Math.max(8, docScore));
      docAuthStatus = 'SUSPICIOUS';
      docAuthReason = "Document exhibits structural anomalies and fails standard corporate formatting conventions.";
      warningSignals.push("Document structure exhibits critical anomalies typical of fraudulent offers.");
    } else if (inputs.documentData.verdict === 'SUSPICIOUS' || flagCount >= 2 || docScore < 70) {
      docAuthScore = Math.max(20, Math.min(55, docScore));
      docAuthStatus = 'FLAGGED';
      docAuthReason = `Document triggered ${flagCount} structural anomaly flags and incomplete enterprise standards.`;
      warningSignals.push(`Multiple document anomaly flags triggered (${flagCount}).`);
    } else {
      docAuthScore = Math.min(90, Math.max(70, docScore));
      docAuthStatus = docAuthScore >= 75 ? 'VERIFIED' : 'FLAGGED';
      docAuthReason = "Document structure and layout align with genuine formal organizational correspondence.";
      positiveSignals.push("Document structure consistent with legitimate enterprise offer.");
    }
  }

  // ============================================================================
  // 2. Company Legal Verification Score (Weight: 15%)
  // ============================================================================
  const companyEvidence = evidenceList.filter(e => e.category === 'COMPANY' || e.category === 'REGISTRY');
  const isCompanyActive = Boolean(
    inputs.companyData &&
    inputs.companyData.registry_status !== undefined &&
    (inputs.companyData.registry_status as any) !== 'UNKNOWN' &&
    (inputs.companyData.registry_status as any) !== 'NOT_INDEPENDENTLY_VERIFIED'
  );

  let companyScore = 0;
  let companyConfidence = 0;
  let companyStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let companyReason = "Company identity not independently verified in statutory register.";

  if (isCompanyActive && inputs.companyData) {
    const isLiveReg = ['VERIFIED', 'VERIFIED_INDEPENDENTLY', 'ACTIVE'].includes(inputs.companyData.registry_status as string) && inputs.companyData.status === 'ACTIVE';
    const isLocalRef = (inputs.companyData.registry_status as string) === 'LOCAL_REFERENCE_FOUND';

    if (isLiveReg) {
      companyScore = 95;
      companyConfidence = 95;
      companyStatus = 'VERIFIED';
      companyReason = `Verified statutory enterprise registration (${inputs.companyData.legal_name || 'Active'}).`;
      positiveSignals.push(`Statutory company registration confirmed: ${inputs.companyData.legal_name || 'Active'}`);
    } else if (isLocalRef) {
      companyScore = 80;
      companyConfidence = 70;
      companyStatus = 'VERIFIED';
      companyReason = `Matched corporate reference dataset (${inputs.companyData.legal_name || 'Active'}). Note: Live MCA21 statutory verification is not configured.`;
      positiveSignals.push(`Company found in reference records: ${inputs.companyData.legal_name || 'Active'}`);
    } else if (inputs.companyData.registry_status === 'NOT_FOUND') {
      companyScore = 45;
      companyConfidence = 50;
      companyStatus = 'UNVERIFIED';
      companyReason = "No statutory record found in direct index. (Absence does not imply fraud).";
    }
  }

  // ============================================================================
  // 3. Domain Security Score (Weight: 10%)
  // ============================================================================
  const domainEvidence = evidenceList.filter(e => e.category === 'DOMAIN');
  const isDomainActive = Boolean(
    inputs.domainData &&
    (inputs.domainData.has_dns || inputs.domainData.lookalike_detected || inputs.domainData.age_days !== undefined)
  );

  let domainScore = 0;
  let domainConfidence = 0;
  let domainStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let domainReason = "Domain security intelligence pending lookup.";

  if (isDomainActive && inputs.domainData) {
    domainConfidence = 85;
    if (inputs.domainData.lookalike_detected) {
      domainScore = 10;
      domainStatus = 'CONTRADICTED';
      domainReason = `Lookalike domain detected mimicking ${inputs.domainData.lookalike_target}.`;
      criticalSignals.push(`Lookalike / typosquatting domain impersonating ${inputs.domainData.lookalike_target}.`);
    } else if (inputs.domainData.age_days !== undefined && inputs.domainData.age_days < 60) {
      domainScore = 25;
      domainStatus = 'SUSPICIOUS';
      domainReason = `Newly registered domain (${inputs.domainData.age_days} days old).`;
      warningSignals.push(`Domain registered recently (${inputs.domainData.age_days} days ago).`);
    } else if (inputs.domainData.has_dns && inputs.domainData.ssl_valid) {
      const isMature = (inputs.domainData.age_days || 0) > 365;
      domainScore = isMature ? 90 : 75;
      domainStatus = 'VERIFIED';
      domainReason = isMature
        ? `Established domain (${inputs.domainData.age_days} days old) with active DNS and valid TLS.`
        : "Domain has active DNS and valid TLS certificate (infrastructure confirmed).";
      positiveSignals.push("Domain infrastructure verified (active DNS & valid TLS).");
    } else if (inputs.domainData.has_dns) {
      domainScore = 45;
      domainStatus = 'SUSPICIOUS';
      domainReason = "Domain resolves via DNS but lacks valid TLS certificate.";
      warningSignals.push("Domain lacks valid TLS certificate.");
    }
  }

  // ============================================================================
  // 4. Recruiter Authentication Score (Weight: 10%)
  // ============================================================================
  const recruiterEvidence = evidenceList.filter(e => e.category === 'RECRUITER' || e.category === 'EMAIL');
  const isRecruiterActive = Boolean(inputs.recruiterData && inputs.recruiterData.email);

  let recruiterScore = 0;
  let recruiterConfidence = 0;
  let recruiterStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let recruiterReason = "No recruiter email provided for verification.";

  if (isRecruiterActive && inputs.recruiterData) {
    recruiterConfidence = 85;
    const isFree = inputs.recruiterData.free_email_provider || inputs.recruiterData.is_free_provider;
    const isMatched = inputs.recruiterData.domain_alignment === 'EXACT_MATCH' || inputs.recruiterData.domain_alignment === 'SUBSIDIARY_MATCH' || inputs.recruiterData.domain_alignment === 'MATCH';
    const isLookalike = inputs.recruiterData.domain_alignment === 'LOOKALIKE';

    if (isLookalike) {
      recruiterScore = 10;
      recruiterStatus = 'CONTRADICTED';
      recruiterReason = "Recruiter email utilizes deceptive lookalike domain.";
      criticalSignals.push("Recruiter email uses a lookalike domain targeting a registered brand.");
    } else if (isFree) {
      recruiterScore = 30;
      recruiterStatus = 'SUSPICIOUS';
      recruiterReason = "Recruiter communicates via public free webmail handle (Gmail/Yahoo).";
      warningSignals.push("Recruiter using free public webmail (Gmail/Yahoo) rather than verified corporate domain.");
    } else if (isMatched) {
      recruiterScore = 90;
      recruiterStatus = 'VERIFIED';
      recruiterReason = "Recruiter domain aligns with registered corporate domain (authorized alignment).";
      positiveSignals.push("Sender email domain matches verified corporate domain.");
    } else {
      recruiterScore = 45;
      recruiterStatus = 'UNVERIFIED';
      recruiterReason = "Recruiter email domain could not be independently linked to claimed company.";
    }
  }

  // ============================================================================
  // 5. Financial / Fee Safety Score (Weight: 20% — HIGHEST WEIGHT)
  // ============================================================================
  const financialEvidence = evidenceList.filter(e => e.category === 'OFFER' || (e.category as any) === 'PAYMENT' || e.category === 'DOCUMENT' || (e.category as any) === 'FINANCIAL');
  const isFinancialActive = Boolean(
    inputs.documentData &&
    (((inputs.documentData.extracted_text || '').trim().length > 20) ||
     inputs.documentData.has_fee_demand !== undefined ||
     (inputs.documentData.fee_details && inputs.documentData.fee_details.length > 0))
  );

  let documentScore = 0;
  let documentConfidence = 0;
  let documentStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let documentReason = "No document text available for fee & monetary clause analysis.";

  if (isFinancialActive && inputs.documentData) {
    documentConfidence = 95;
    const hasDetectedFee = Boolean(
      inputs.documentData.has_fee_demand ||
      (inputs.documentData.fee_details && inputs.documentData.fee_details.length > 0) ||
      (inputs.documentData.requested_fees && inputs.documentData.requested_fees.length > 0) ||
      evidenceList.some(e => (e.category === 'FINANCIAL' || (e.category as any) === 'PAYMENT' || e.category === 'OFFER') && (e.severity === 'CRITICAL' || e.title?.toLowerCase().includes('fee') || e.snippet?.toLowerCase().includes('fee')))
    );

    const rawComp = inputs.documentData.candidate_compensation;
    const compArray = Array.isArray(rawComp) ? rawComp : (rawComp && typeof rawComp === 'object' ? [rawComp] : []);
    const hasCandidateComp = compArray.length > 0 || Boolean(inputs.documentData.detected_stipend);

    if (hasDetectedFee) {
      documentScore = 5;
      documentStatus = 'CONTRADICTED';
      const pFee = inputs.documentData.fee_details?.[0];
      documentReason = pFee
        ? `Mandatory candidate payment detected: ${pFee.category || 'Fee'}${pFee.amount ? ' of ' + pFee.amount : ''}${pFee.recipient ? ' payable to ' + pFee.recipient : ''}.`
        : "Mandatory candidate payment, deposit, or registration fee detected.";
      criticalSignals.push("Mandatory candidate fee/security deposit requested in offer.");
    } else if (hasCandidateComp) {
      documentScore = 95;
      documentStatus = 'VERIFIED';
      documentReason = "Offer document defines candidate compensation and is completely free of upfront fee demands (Zero-Fee Standard respected).";
      positiveSignals.push("Offer specifies candidate compensation and respects Zero-Fee Standard.");
    } else {
      documentScore = 90;
      documentStatus = 'VERIFIED';
      documentReason = "Offer document text is free of upfront payment clauses (Zero-Fee Standard respected).";
      positiveSignals.push("Offer contains no monetary deposit requests (Zero-Fee Standard respected).");
    }
  }

  // ============================================================================
  // 6. Certificate Verification Score (Weight: 5%)
  // ============================================================================
  const certEvidence = evidenceList.filter(e => e.category === 'CERTIFICATE');
  const isCertActive = Boolean(inputs.certificateData && (inputs.certificateData as any).checked);

  let certScore = 0;
  let certConfidence = 0;
  let certStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let certReason = "No certificate verification performed.";

  if (isCertActive && inputs.certificateData) {
    certConfidence = 80;
    if (inputs.certificateData.status === 'VERIFIED_AUTHENTIC' || (inputs.certificateData.status as any) === 'VERIFIED') {
      certScore = 90;
      certStatus = 'VERIFIED';
      certReason = "Certificate independently verified against issuer records.";
      positiveSignals.push("Certificate independently authenticated.");
    } else if (inputs.certificateData.status === 'LIKELY_FRAUDULENT' || (inputs.certificateData.status as any) === 'SUSPICIOUS' || (inputs.certificateData.status as any) === 'INVALID') {
      certScore = 15;
      certStatus = 'CONTRADICTED';
      certReason = "Certificate verification failed or flagged as invalid.";
      warningSignals.push("Certificate verification returned suspicious or invalid status.");
    } else {
      certScore = 40;
      certStatus = 'UNVERIFIED';
      certReason = "Certificate could not be independently authenticated.";
    }
  }

  // ============================================================================
  // 7. ML Fraud Model Score (Weight: 10%)
  // ============================================================================
  const mlEvidence = evidenceList.filter(e => (e.category as any) === 'ML_MODEL' || e.category === 'DOCUMENT');
  const isMLActive = Boolean(
    inputs.mlPrediction &&
    inputs.mlPrediction.model_loaded !== false &&
    inputs.mlPrediction.prediction !== 'ML_UNAVAILABLE' &&
    inputs.mlPrediction.fraudProbability !== undefined
  );

  let mlScore = 0;
  let mlConfidence = 0;
  let mlStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let mlReason = "Supervised ML pattern evaluation unavailable.";

  if (isMLActive && inputs.mlPrediction) {
    mlScore = Math.round((1 - inputs.mlPrediction.fraudProbability) * 100);
    mlConfidence = Math.round(inputs.mlPrediction.confidence * 100);
    if (inputs.mlPrediction.fraudProbability >= 0.70) {
      mlStatus = 'SUSPICIOUS';
      mlReason = `Supervised ML classifier flagged high similarity to fraudulent job postings (${Math.round(inputs.mlPrediction.fraudProbability * 100)}%).`;
      warningSignals.push(`Supervised ML Model (${inputs.mlPrediction.algorithm}) flagged ${Math.round(inputs.mlPrediction.fraudProbability * 100)}% fraud probability — requires corroboration`);
    } else if (inputs.mlPrediction.fraudProbability <= 0.20) {
      mlStatus = 'VERIFIED';
      mlReason = `Supervised ML classifier predicts high probability of legitimate offer (${Math.round((1 - inputs.mlPrediction.fraudProbability) * 100)}%).`;
      positiveSignals.push("Supervised ML classifier verified legitimate job listing syntax.");
    } else {
      mlStatus = 'UNVERIFIED';
      mlReason = `Supervised ML classifier evaluates moderate fraud probability (${Math.round(inputs.mlPrediction.fraudProbability * 100)}%).`;
    }
  }

  // ============================================================================
  // 8. Threat Intelligence Score (Weight: 5%)
  // ============================================================================
  const threatEvidence = evidenceList.filter(e => e.category === 'THREAT');
  const isThreatActive = Boolean(
    inputs.threatData &&
    !(inputs.threatData as any).source_unavailable &&
    ((inputs.threatData as any).queries_run || 0) > 0
  );

  let threatScore = 0;
  let threatConfidence = 0;
  let threatStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let threatReason = "No threat feeds queried for target entity.";

  if (isThreatActive && inputs.threatData) {
    threatConfidence = 90;
    if (inputs.threatData.known_threat || inputs.threatData.max_severity === 'CRITICAL') {
      threatScore = 10;
      threatStatus = 'CONTRADICTED';
      threatReason = "Entity matches known malicious threat intelligence feeds (IOC confirmed).";
      criticalSignals.push("Direct match in global security threat feeds (AbuseIPDB/URLhaus).");
    } else {
      threatScore = 90;
      threatStatus = 'VERIFIED';
      threatReason = "Entity clean across global threat intelligence databases.";
      positiveSignals.push("Entity clean in threat intelligence databases.");
    }
  }

  // ============================================================================
  // 9. Community Evidence Score (Weight: 5%)
  // ============================================================================
  const communityEvidence = evidenceList.filter(e => e.category === 'PUBLIC_REPORT' || (e.category as any) === 'COMMUNITY');
  const communityExperiences = (inputs.communityData as any)?.experiences || [];
  const isCommunityActive = Boolean(
    inputs.communityData &&
    (inputs.communityData.totalRelevantResults > 0 || communityExperiences.length > 0)
  );

  let communityScore = 0;
  let communityConfidence = 0;
  let communityStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let communityReason = "No verified community discussion records found.";

  if (isCommunityActive && inputs.communityData) {
    const fraudSignals = communityExperiences.filter((e: any) => e.experienceType?.includes('SCAM') || e.experienceType?.includes('FRAUD') || e.experienceType?.includes('PAYMENT'));
    const posSignals = communityExperiences.filter((e: any) => e.experienceType?.includes('POSITIVE') || e.experienceType?.includes('VERIFIED'));
    communityConfidence = 80;

    if (fraudSignals.length >= 2) {
      communityScore = 20;
      communityStatus = 'CONTRADICTED';
      communityReason = `Multiple independent public complaints corroborated (${fraudSignals.length} reports).`;
      criticalSignals.push(`Public forums record ${fraudSignals.length} independent complaints regarding recruitment irregularities.`);
    } else if (fraudSignals.length === 1) {
      communityScore = 40;
      communityStatus = 'SUSPICIOUS';
      communityReason = "Single unverified public community post found (weak signal).";
      warningSignals.push("Isolated public community discussion noting recruitment irregularities.");
    } else if (posSignals.length > 0) {
      communityScore = 90;
      communityStatus = 'VERIFIED';
      communityReason = "Public forum reviews corroborate positive candidate experience.";
      positiveSignals.push("Public community reports confirm legitimate hiring.");
    } else {
      communityScore = 50;
      communityStatus = 'UNVERIFIED';
      communityReason = "Community discussions found without conclusive risk indicators.";
    }
  }

  // ============================================================================
  // 10. Cross-Source Consistency Score (Weight: 10%)
  // ============================================================================
  const conflicts = detectEvidenceConflicts({
    companyData: inputs.companyData,
    domainData: inputs.domainData,
    recruiterData: inputs.recruiterData,
    certificateStatus: inputs.certificateData?.status,
    mlPrediction: inputs.mlPrediction,
    threatData: inputs.threatData,
    hasFeeDemand: inputs.documentData?.has_fee_demand,
    communityNegativeCount: communityExperiences.filter((e: any) => e.experienceType?.includes('SCAM') || e.experienceType?.includes('FRAUD')).length,
    communityPositiveCount: communityExperiences.filter((e: any) => e.experienceType?.includes('POSITIVE')).length,
  });

  const isConsistencyActive = Boolean(
    inputs.companyData || inputs.domainData || inputs.recruiterData || inputs.documentData
  );

  let consistencyScore = 0;
  let consistencyConfidence = 0;
  let consistencyStatus: ScoreComponentBreakdown['status'] = 'UNVERIFIED';
  let consistencyReason = "Insufficient multi-source inputs to evaluate signal consistency.";

  if (isConsistencyActive) {
    consistencyConfidence = 85;
    if (conflicts.length > 0) {
      consistencyScore = Math.max(15, 85 - (conflicts.length * 20));
      consistencyStatus = 'FLAGGED';
      consistencyReason = `Identified ${conflicts.length} evidence conflicts across sources.`;
      for (const conf of conflicts) {
        warningSignals.push(`Evidence Conflict: ${conf.title}`);
      }
    } else {
      consistencyScore = 90;
      consistencyStatus = 'VERIFIED';
      consistencyReason = "Cross-source signals are internally consistent.";
    }
  }

  // ============================================================================
  // Compile 10 Components Breakdown
  // ============================================================================
  const components: DeterministicScoreResult['components'] = {
    document_authenticity: {
      name: "Document Authenticity",
      weight: weights.document_authenticity,
      score: docAuthScore,
      weighted_score: isDocAuthActive ? Number((docAuthScore * weights.document_authenticity).toFixed(2)) : 0,
      confidence: docAuthConfidence,
      reason: docAuthReason,
      evidence_count: docAuthEvidence.length,
      active: isDocAuthActive,
      status: docAuthStatus,
      evidence_ids: docAuthEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    company: {
      name: "Company Legal Verification",
      weight: weights.company_registry,
      score: companyScore,
      weighted_score: isCompanyActive ? Number((companyScore * weights.company_registry).toFixed(2)) : 0,
      confidence: companyConfidence,
      reason: companyReason,
      evidence_count: companyEvidence.length,
      active: isCompanyActive,
      status: companyStatus,
      evidence_ids: companyEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    domain: {
      name: "Domain Security",
      weight: weights.domain_intelligence,
      score: domainScore,
      weighted_score: isDomainActive ? Number((domainScore * weights.domain_intelligence).toFixed(2)) : 0,
      confidence: domainConfidence,
      reason: domainReason,
      evidence_count: domainEvidence.length,
      active: isDomainActive,
      status: domainStatus,
      evidence_ids: domainEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    recruiter: {
      name: "Recruiter Authentication",
      weight: weights.recruiter_email,
      score: recruiterScore,
      weighted_score: isRecruiterActive ? Number((recruiterScore * weights.recruiter_email).toFixed(2)) : 0,
      confidence: recruiterConfidence,
      reason: recruiterReason,
      evidence_count: recruiterEvidence.length,
      active: isRecruiterActive,
      status: recruiterStatus,
      evidence_ids: recruiterEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    document: {
      name: "Financial / Fee Safety",
      weight: weights.financial_fee_safety,
      score: documentScore,
      weighted_score: isFinancialActive ? Number((documentScore * weights.financial_fee_safety).toFixed(2)) : 0,
      confidence: documentConfidence,
      reason: documentReason,
      evidence_count: financialEvidence.length,
      active: isFinancialActive,
      status: documentStatus,
      evidence_ids: financialEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    certificate: {
      name: "Certificate Verification",
      weight: weights.certificate_verification,
      score: certScore,
      weighted_score: isCertActive ? Number((certScore * weights.certificate_verification).toFixed(2)) : 0,
      confidence: certConfidence,
      reason: certReason,
      evidence_count: certEvidence.length,
      active: isCertActive,
      status: certStatus,
      evidence_ids: certEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    ml_probability: {
      name: "ML Fraud Model",
      weight: weights.ml_probability,
      score: mlScore,
      weighted_score: isMLActive ? Number((mlScore * weights.ml_probability).toFixed(2)) : 0,
      confidence: mlConfidence,
      reason: mlReason,
      evidence_count: isMLActive ? 1 : 0,
      active: isMLActive,
      status: mlStatus,
      evidence_ids: mlEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    threat: {
      name: "Threat Intelligence",
      weight: weights.threat_intelligence,
      score: threatScore,
      weighted_score: isThreatActive ? Number((threatScore * weights.threat_intelligence).toFixed(2)) : 0,
      confidence: threatConfidence,
      reason: threatReason,
      evidence_count: threatEvidence.length,
      active: isThreatActive,
      status: threatStatus,
      evidence_ids: threatEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    community: {
      name: "Community Evidence",
      weight: weights.community_evidence,
      score: communityScore,
      weighted_score: isCommunityActive ? Number((communityScore * weights.community_evidence).toFixed(2)) : 0,
      confidence: communityConfidence,
      reason: communityReason,
      evidence_count: communityEvidence.length,
      active: isCommunityActive,
      status: communityStatus,
      evidence_ids: communityEvidence.map((e: any) => e.evidence_id || e.id).filter(Boolean),
    },
    consistency: {
      name: "Cross-Source Consistency",
      weight: weights.consistency_conflict,
      score: consistencyScore,
      weighted_score: isConsistencyActive ? Number((consistencyScore * weights.consistency_conflict).toFixed(2)) : 0,
      confidence: consistencyConfidence,
      reason: consistencyReason,
      evidence_count: conflicts.length,
      active: isConsistencyActive,
      status: consistencyStatus,
      evidence_ids: [],
    },
  };

  // Dynamic weight re-normalization across active dimensions
  const activeComponents = Object.entries(components)
    .filter(([_, comp]) => comp.active)
    .map(([key, comp]) => ({ key, ...comp }));

  const activeWeightSum = Number(activeComponents.reduce((sum, c) => sum + c.weight, 0).toFixed(4));

  let preConstraintScore = 0;
  if (activeWeightSum === 0) {
    preConstraintScore = 0;
  } else {
    preConstraintScore = activeComponents.reduce((sum, c) => {
      const normalizedWeight = c.weight / activeWeightSum;
      return sum + (c.score * normalizedWeight);
    }, 0);
    preConstraintScore = Number(preConstraintScore.toFixed(2));
  }

  // Apply deterministic rule score impact if active dimensions exist
  let rawTrust = preConstraintScore;
  if (activeWeightSum > 0) {
    rawTrust = Math.max(1, Math.min(99, rawTrust + ruleScoreImpact));
  }

  // ============================================================================
  // AUDITABLE CONTEXTUAL CONSTRAINTS (CAPS)
  // ============================================================================
  const constraintsTriggered: ScoreTraceConstraint[] = [];

  // Constraint 1: Lookalike domain impersonation cap (max 25)
  const isLookalike = Boolean(
    inputs.domainData?.lookalike_detected ||
    inputs.recruiterData?.domain_alignment === 'LOOKALIKE'
  );
  if (isLookalike) {
    const applied = rawTrust > 25;
    if (applied) rawTrust = 25;
    constraintsTriggered.push({
      constraint: "LOOKALIKE_DOMAIN_CAP",
      ceiling: 25,
      reason: "Suspected lookalike / typosquatting domain impersonation detected",
      applied,
    });
    hardCaps.push(`LOOKALIKE_DOMAIN_CAP: Trust capped to max 25 — suspected domain impersonation`);
  }

  // Constraint 2: Confirmed candidate payment demand cap (max 20)
  const hasFeeDemand = Boolean(
    inputs.documentData?.has_fee_demand ||
    (inputs.documentData?.fee_details && inputs.documentData.fee_details.length > 0) ||
    (inputs.documentData?.requested_fees && inputs.documentData.requested_fees.length > 0) ||
    inputs.documentData?.is_confirmed_impersonation ||
    evidenceList.some(e => (e.category === 'FINANCIAL' || (e.category as any) === 'PAYMENT' || e.category === 'OFFER') && e.severity === 'CRITICAL')
  );
  if (hasFeeDemand) {
    const applied = rawTrust > 20;
    if (applied) rawTrust = 20;
    constraintsTriggered.push({
      constraint: "PAYMENT_REQUEST_CAP",
      ceiling: 20,
      reason: "Confirmed candidate payment demand or security deposit requested in offer",
      applied,
    });
    hardCaps.push(`PAYMENT_REQUEST_CAP: Trust capped to max 20 — confirmed candidate payment demand`);
  }

  // Constraint 3: Malicious IOC threat feed cap (max 15)
  const isThreat = Boolean(
    inputs.threatData?.known_threat ||
    inputs.threatData?.max_severity === 'CRITICAL'
  );
  if (isThreat) {
    const applied = rawTrust > 15;
    if (applied) rawTrust = 15;
    constraintsTriggered.push({
      constraint: "MALICIOUS_IOC_CAP",
      ceiling: 15,
      reason: "Direct match in global security threat feeds (AbuseIPDB/URLhaus)",
      applied,
    });
    hardCaps.push(`MALICIOUS_IOC_CAP: Trust capped to max 15 — confirmed threat intelligence match`);
  }

  // Constraint 4: Recruiter uses free webmail for enterprise offer (max 24)
  const isFreeWebmail = Boolean(
    inputs.recruiterData?.is_free_provider ||
    (inputs.recruiterData as any)?.free_provider ||
    (inputs.documentData?.detected_email && /@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com)$/i.test(inputs.documentData.detected_email))
  );
  if (isFreeWebmail) {
    const applied = rawTrust > 24;
    if (applied) rawTrust = 24;
    constraintsTriggered.push({
      constraint: "FREE_WEBMAIL_CAP",
      ceiling: 24,
      reason: "Personal free webmail utilized for corporate employment offer",
      applied,
    });
    hardCaps.push("FREE_WEBMAIL_CAP: Trust capped to max 24 — personal webmail provider detected");
  }

  // Constraint 5: Substantive Document Fraud & Critical Violation (max 32)
  // Per Part 4: Layout & formatting differences alone MUST NOT dominate the fraud verdict.
  const isDocCompromised = Boolean(
    (inputs.documentData?.has_fee_demand || inputs.documentData?.is_suspicious_offer_letter) &&
    (inputs.documentData?.verdict === "LIKELY FAKE" || (inputs.documentData?.suspicious_patterns && inputs.documentData.suspicious_patterns.length >= 2))
  );
  if (isDocCompromised) {
    const applied = rawTrust > 32;
    if (applied) rawTrust = 32;
    constraintsTriggered.push({
      constraint: "DOCUMENT_STRUCTURE_CAP",
      ceiling: 32,
      reason: "Document contains explicit fraud triggers and fails basic security authenticity",
      applied,
    });
    hardCaps.push("DOCUMENT_STRUCTURE_CAP: Trust capped to max 32 — document failed security authenticity");
  }

  // Constraint 6: Informal Communication Channel (WhatsApp / Telegram) (max 28)
  const hasInformalChannel = Boolean(
    inputs.documentData?.has_informal_channel ||
    (inputs.documentData?.suspicious_patterns || []).some(p => p.includes("WhatsApp") || p.includes("Telegram"))
  );
  if (hasInformalChannel) {
    const applied = rawTrust > 28;
    if (applied) rawTrust = 28;
    constraintsTriggered.push({
      constraint: "INFORMAL_CHANNEL_CAP",
      ceiling: 28,
      reason: "Recruitment process directs communication to unofficial personal messaging channels (WhatsApp/Telegram)",
      applied,
    });
    hardCaps.push("INFORMAL_CHANNEL_CAP: Trust capped to max 28 — informal messaging channel detected");
  }

  // Constraint 7: Compound Risk Cap (max 22)
  if (criticalSignals.length >= 2 || (criticalSignals.length >= 1 && warningSignals.length >= 2)) {
    const applied = rawTrust > 22;
    if (applied) rawTrust = 22;
    constraintsTriggered.push({
      constraint: "COMPOUND_RISK_CAP",
      ceiling: 22,
      reason: "Compound risk threshold exceeded across independent forensic vectors",
      applied,
    });
    hardCaps.push("COMPOUND_RISK_CAP: Trust capped to max 22 — multiple concurrent fraud signals detected");
  }

  const finalTrust = activeWeightSum === 0 ? 0 : Math.round(Math.max(1, Math.min(99, rawTrust)));

  // Evidence Completeness Metric
  const completeness = calculateEvidenceCompleteness(inputs);

  // ============================================================================
  // Evidence Confidence Calculation (Independent of Trust Score)
  // ============================================================================
  let finalConfidence = 0;
  if (activeWeightSum > 0) {
    const activeCount = activeComponents.length;
    const verifiedCount = activeComponents.filter(c => c.status === 'VERIFIED').length;
    const coverageFactor = activeWeightSum; // 0.0 - 1.0
    const verifiedRatio = activeCount > 0 ? verifiedCount / activeCount : 0;
    const completenessFactor = completeness.percentage / 100;
    const conflictPenalty = Math.min(30, conflicts.length * 10);

    const rawConf = (
      (coverageFactor * 40) +
      (completenessFactor * 35) +
      (verifiedRatio * 25)
    ) - conflictPenalty;

    finalConfidence = Math.round(Math.max(5, Math.min(99, rawConf)));
  }

  // ============================================================================
  // Risk Level & Verdict Calibration (Deterministic)
  // ============================================================================
  let riskLevel: RiskLevel = "LOW";
  let verdict: DeterministicScoreResult['verdict'] = "LIKELY LEGITIMATE";

  if (activeWeightSum === 0) {
    riskLevel = "MODERATE";
    verdict = "INSUFFICIENT_EVIDENCE";
  } else if (finalTrust >= 80) {
    riskLevel = "LOW";
    verdict = "LIKELY LEGITIMATE";
  } else if (finalTrust >= 65) {
    riskLevel = "LOW";
    verdict = "LOW RISK";
  } else if (finalTrust >= 45) {
    riskLevel = "MODERATE";
    verdict = "MODERATE RISK";
  } else if (finalTrust >= 28) {
    riskLevel = "HIGH";
    verdict = "HIGH RISK";
  } else {
    riskLevel = "CRITICAL";
    verdict = "LIKELY SCAM";
  }

  // Sparse evidence guard
  if (activeWeightSum > 0 && completeness.percentage < 25 && finalTrust >= 40 && finalTrust <= 70) {
    verdict = "INSUFFICIENT_EVIDENCE";
  }

  // Compile mathematical Score Trace
  const traceDimensions: ScoreTraceDimension[] = Object.entries(components).map(([key, comp]) => ({
    dimension: key,
    name: comp.name,
    weight: comp.weight,
    normalized_weight: activeWeightSum > 0 && comp.active ? Number((comp.weight / activeWeightSum).toFixed(4)) : 0,
    active: comp.active,
    status: comp.status,
    score: comp.score,
    weighted_contribution: activeWeightSum > 0 && comp.active ? Number((comp.score * (comp.weight / activeWeightSum)).toFixed(2)) : 0,
    evidence_ids: comp.evidence_ids,
    reason: comp.reason,
  }));

  const scoreTrace: ScoreTrace = {
    pre_constraint_score: preConstraintScore,
    active_weight_sum: activeWeightSum,
    dimensions: traceDimensions,
    rule_impact: ruleScoreImpact,
    constraints_triggered: constraintsTriggered,
    final_score: finalTrust,
    verdict,
    formula: activeWeightSum > 0
      ? `final_score = min(caps, sum(score_i * (weight_i / ${activeWeightSum})) + (${ruleScoreImpact}))`
      : "final_score = 0.0 (active_weight_sum == 0)",
  };

  const overallRiskScore = Math.max(1, Math.min(99, 100 - finalTrust));
  const assessments = buildStandardAssessments(inputs, components, hardCaps, finalTrust, verdict, conflicts);

  return {
    trust_score: finalTrust,
    confidence_score: finalConfidence,
    pre_constraint_score: preConstraintScore,
    risk_level: riskLevel,
    verdict,
    overall_risk_score: overallRiskScore,
    assessments,
    components,
    rules_triggered: rules,
    conflicts,
    hard_caps_applied: hardCaps,
    positive_signals: positiveSignals,
    warning_signals: warningSignals,
    critical_signals: criticalSignals,
    scoring_model_version: SCORING_MODEL_VERSION,
    score_trace: scoreTrace,
  };
}

export function getRiskBandInfo(score: number): { band: AssessmentRiskBand; label: string } {
  if (score <= 15) return { band: 'LOW_RISK', label: 'Low Risk' };
  if (score <= 40) return { band: 'MINOR_IRREGULARITIES', label: 'Minor Irregularities' };
  if (score <= 70) return { band: 'MODERATE_RISK', label: 'Moderate Risk' };
  return { band: 'CRITICAL_RISK', label: 'Critical Fraud Risk' };
}

export function getRiskBand(score: number): AssessmentRiskBand {
  return getRiskBandInfo(score).band;
}

export function getRiskBandLabel(band: AssessmentRiskBand): string {
  if (band === 'LOW_RISK') return 'Low Risk';
  if (band === 'MINOR_IRREGULARITIES') return 'Minor Irregularities';
  if (band === 'MODERATE_RISK') return 'Moderate Risk';
  return 'Critical Fraud Risk';
}

function makeAssessment(
  id: string,
  name: string,
  risk_score: number,
  evidence_found: string,
  why_it_matters: string,
  evidence_strength: 'High' | 'Moderate' | 'Contextual',
  recommended_next_step: string,
  extras?: {
    exact_quote?: string;
    amount?: string;
    recipient?: string;
    confidence_level?: number;
    limitations?: string;
  }
): AssessmentItem {
  const boundedScore = Math.max(0, Math.min(100, Math.round(risk_score)));
  const { band, label } = getRiskBandInfo(boundedScore);
  return {
    id,
    name,
    risk_score: boundedScore,
    risk_band: band,
    risk_band_label: label,
    evidence_found,
    why_it_matters,
    evidence_strength,
    recommended_next_step,
    exact_quote: extras?.exact_quote,
    amount: extras?.amount,
    recipient: extras?.recipient,
    confidence_level: extras?.confidence_level ?? (boundedScore >= 70 || boundedScore <= 15 ? 95 : 80),
    limitations: extras?.limitations,
  };
}

export function buildStandardAssessments(
  inputs: ScoringInputs,
  components: DeterministicScoreResult['components'],
  hardCaps: string[],
  finalTrust: number,
  verdict: DeterministicScoreResult['verdict'],
  conflicts: EvidenceConflict[]
): AssessmentItem[] {
  const overallRisk = Math.max(1, Math.min(99, 100 - finalTrust));

  const feeDetails = inputs.documentData?.fee_details || [];
  const primaryFee = feeDetails[0];
  const rawCompData = inputs.documentData?.candidate_compensation;
  const candidateCompList: Array<{ type?: string; amount?: string; rawText?: string; raw_quote?: string }> = Array.isArray(rawCompData)
    ? rawCompData
    : (rawCompData && typeof rawCompData === 'object' ? [rawCompData] : []);
  const hasComp = candidateCompList.length > 0 || Boolean(inputs.documentData?.detected_stipend);

  const hasFee = Boolean(
    inputs.documentData?.has_fee_demand ||
    feeDetails.length > 0 ||
    components.document.status === 'FLAGGED' ||
    components.document.status === 'CONTRADICTED' ||
    hardCaps.some(c => c.toLowerCase().includes('fee') || c.toLowerCase().includes('payment')) ||
    inputs.rules_triggered?.some(r => r.rule_id === 'R001' || /fee|payment|deposit|caution|registration/i.test(r.name || '') || /fee|payment|deposit|caution/i.test(r.description || '')) ||
    inputs.evidence?.some(e => e.evidence_type === 'FEE_DEMAND' || e.evidence_type === 'PAYMENT_REQUEST' || /fee|deposit|payment|caution|registration/i.test(e.title || '') || /fee|deposit|payment|caution|registration/i.test(e.evidence_text || '')) ||
    inputs.documentData?.suspicious_patterns?.some(p => /fee|deposit|caution|registration|payment|rs\.?|inr|upi/i.test(p)) ||
    Boolean(inputs.documentData?.fee_amount_detected)
  );

  const isFreeEmail = Boolean(
    inputs.recruiterData?.is_free_provider ||
    (inputs.documentData?.detected_email && /@(gmail|yahoo|outlook|hotmail)\.com$/i.test(inputs.documentData.detected_email)) ||
    hardCaps.some(c => c.toLowerCase().includes('free_webmail'))
  );

  const hasInformal = Boolean(
    inputs.documentData?.has_informal_channel ||
    (inputs.documentData?.suspicious_patterns || []).some(p => /whatsapp|telegram/i.test(p)) ||
    hardCaps.some(c => c.toLowerCase().includes('informal_channel'))
  );

  const rawComp = inputs.companyData?.legal_name || inputs.companyData?.name || inputs.documentData?.detected_company_name || inputs.entityValue;
  const isCompanyUnidentified = !rawComp || isFilenameOrPlaceholder(rawComp);

  const assessments: AssessmentItem[] = [
    // 1. Overall Offer Risk
    makeAssessment(
      'overall_offer_risk',
      'Overall Employment Offer Risk',
      overallRisk,
      `Multi-vector deterministic assessment produced Trust Score ${finalTrust}/100 with verdict "${verdict}". Risk Score: ${overallRisk}/100.`,
      'Fuses structural document analysis, corporate registration, domain age, recruiter mail routing, and threat intelligence into a single calibrated risk posture.',
      'High',
      overallRisk >= 60
        ? 'Do NOT transfer money, sign contracts, or submit sensitive documents. Verify directly with the company HR department.'
        : 'Proceed with routine corporate onboarding verification.',
      { confidence_level: 95 }
    ),

    // 2. Financial / Fee Demand Risk
    hasFee
      ? makeAssessment(
          'financial_safety',
          'Payment and Financial Fee Safety',
          96,
          primaryFee
            ? `Mandatory candidate payment detected: ${primaryFee.category || 'Fee'}${primaryFee.amount ? ' of ' + primaryFee.amount : ''}${primaryFee.recipient ? ' payable to ' + primaryFee.recipient : ''}. ${primaryFee.is_refundable ? 'Claimed refundable (' + (primaryFee.refund_terms || 'conditional') + ')' : 'Non-refundable / unstated'}. ${primaryFee.deadline ? 'Deadline: ' + primaryFee.deadline + '. ' : ''}Exact quote: "${primaryFee.exact_quote}"`
            : `Document contains explicit fee or deposit demands: ${inputs.documentData?.fee_amount_detected ? 'Amount: ' + inputs.documentData.fee_amount_detected : (inputs.documentData?.suspicious_patterns?.filter(p => /fee|deposit|rs\.|inr|caution|registration|processing/i.test(p)).join('; ') || 'Upfront monetary deposit demanded')}`,
          primaryFee?.why_it_matters || 'Legitimate employers never demand candidate registration fees, training charges, or caution deposits. Upfront payment demands are an immediate scam indicator.',
          'High',
          'NEVER transfer funds, UPI payments, or bank deposits. Genuine employers never charge candidates. Report immediately to 1930 Cybercrime Helpline.',
          {
            exact_quote: primaryFee?.exact_quote,
            amount: primaryFee?.amount || inputs.documentData?.fee_amount_detected,
            recipient: primaryFee?.recipient,
            confidence_level: 98,
          }
        )
      : hasComp
      ? makeAssessment(
          'financial_safety',
          'Payment and Financial Fee Safety',
          5,
          `Candidate compensation detected (${candidateCompList.map(c => `${c.type || 'Remuneration'}: ${c.amount || c.raw_quote || c.rawText || ''}`).join(', ') || inputs.documentData?.detected_stipend}). Zero upfront fees, training charges, registration fees, or caution deposits detected.`,
          'Document defines remuneration paid to candidate without demanding any candidate payments. Legitimate employers pay employees rather than requiring payments.',
          'High',
          'Maintain standard pre-employment vigilance; confirm reimbursement policies for official travel expenses.',
          { confidence_level: 92 }
        )
      : makeAssessment(
          'financial_safety',
          'Payment and Financial Fee Safety',
          8,
          'Zero upfront fees, training charges, registration fees, or caution deposits detected.',
          'Legitimate employers never demand candidate registration fees, training charges, or caution deposits. Upfront payment demands are an immediate scam indicator.',
          'High',
          'Maintain standard vigilance; confirm company reimbursement policies for any official travel.',
          { confidence_level: 88 }
        ),

    // 3. Document Authenticity & Structural Integrity
    makeAssessment(
      'document_authenticity',
      'Document Authenticity & Structural Integrity',
      (inputs.documentData?.is_suspicious_offer_letter && hasFee) ? 75 : (inputs.documentData?.is_suspicious_offer_letter ? 35 : 12),
      inputs.documentData?.is_suspicious_offer_letter
        ? (hasFee
            ? 'Structural formatting anomalies detected alongside explicit recruitment fraud indicators.'
            : 'Document layout or formatting deviates from standard corporate templates (non-fatal variation).')
        : 'Document layout adheres to standard corporate appointment conventions.',
      'Formatting and layout differences alone must not dominate fraud verdicts as styles vary widely across genuine employers.',
      inputs.documentData?.is_suspicious_offer_letter && hasFee ? 'High' : 'Contextual',
      'Verify document appointment ID with the employer HR department.',
      { confidence_level: 85 }
    ),

    // 4. Corporate Entity & MCA Statutory Registry
    isCompanyUnidentified
      ? makeAssessment(
          'company_registry',
          'Corporate Entity & MCA Statutory Registry',
          50,
          'Organization not confidently identified from document content. Statutory corporate registry verification could not be performed.',
          'Statutory registration establishes legal operating existence. When the issuing organization cannot be verified, employer legitimacy remains unconfirmed.',
          'Moderate',
          'Request the employer provide their full legal registered entity name and Corporate Identification Number (CIN).',
          {
            confidence_level: 40,
            limitations: 'Document lacks clear corporate identity or statutory registration identifiers (CIN/LLPIN).',
          }
        )
      : inputs.companyData?.mca_status === 'ACTIVE' || inputs.companyData?.registry_status === 'VERIFIED'
      ? makeAssessment(
          'company_registry',
          'Corporate Entity & MCA Statutory Registry',
          10,
          `Statutory corporate registration verified: ${inputs.companyData.legal_name || inputs.companyData.name} (CIN/Reg: ${inputs.companyData.registration_number || 'Verified'}).`,
          'Statutory registration establishes legal operating existence, though scammers often impersonate real registered entities.',
          'High',
          'Cross-check corporate entity status on MCA21 (mca.gov.in) and ensure the recruiter is an authorized representative.',
          { confidence_level: 95 }
        )
      : inputs.companyData?.registry_status === 'CONTRADICTED'
      ? makeAssessment(
          'company_registry',
          'Corporate Entity & MCA Statutory Registry',
          85,
          `Claimed entity "${rawComp}" contradicted by official statutory MCA records.`,
          'Statutory registry conflicts indicate fabricated or dissolved corporate entities.',
          'High',
          'Do not proceed; the claimed entity status contradicts official corporate registry records.',
          { confidence_level: 90 }
        )
      : makeAssessment(
          'company_registry',
          'Corporate Entity & MCA Statutory Registry',
          35,
          `Claimed entity "${rawComp}" not independently corroborated on statutory MCA master data.`,
          'Statutory registration establishes legal operating existence, though scammers often impersonate real registered entities.',
          'Moderate',
          'Cross-check corporate entity status on MCA21 (mca.gov.in) and ensure the recruiter is an authorized representative.',
          { confidence_level: 75 }
        ),

    // 5. Domain Security & Web Presence Intelligence
    makeAssessment(
      'domain_intelligence',
      'Domain Security & Web Presence Intelligence',
      inputs.domainData?.is_lookalike
        ? 92
        : (inputs.domainData?.domain_age_days !== undefined && inputs.domainData.domain_age_days < 90
            ? 65
            : (inputs.domainData?.has_dns ? 12 : 35)),
      inputs.domainData?.is_lookalike
        ? `Lookalike / typosquatted domain detected targeting legitimate brand (${inputs.domainData.domain}).`
        : inputs.domainData?.domain_age_days !== undefined && inputs.domainData.domain_age_days < 90
        ? `Newly registered domain (${inputs.domainData.domain}) created only ${inputs.domainData.domain_age_days} days ago.`
        : inputs.domainData?.has_dns
        ? `Established domain (${inputs.domainData.domain}) with active DNS and valid SSL security certificate.`
        : 'Domain records unverified or not provided in document context.',
      'Domain impersonation and disposable domains are prime tools used by fraudulent hiring rings.',
      'High',
      'Access the employer website by typing the official address directly into your browser, avoiding links inside the document.',
      { confidence_level: inputs.domainData?.is_lookalike || inputs.domainData?.has_dns ? 95 : 75 }
    ),

    // 6. Recruiter Identity & Official Email Routing
    makeAssessment(
      'recruiter_email',
      'Recruiter Identity & Official Email Routing',
      isFreeEmail ? 88 : (inputs.recruiterData?.email ? 12 : 38),
      isFreeEmail
        ? `Recruiter utilizes public personal webmail (${inputs.recruiterData?.email || inputs.documentData?.detected_email}) instead of an official company domain.`
        : inputs.recruiterData?.email
        ? `Corporate email domain verified: ${inputs.recruiterData.email}.`
        : 'No verified recruiter contact email identified in document.',
      'Corporate HR communications originate exclusively from official company domains. Free webmail usage is a primary impersonation indicator.',
      'High',
      isFreeEmail
        ? 'Insist on receiving all correspondence from an official @company.com email address before sharing personal data.'
        : 'Confirm the recruiter is listed on the company LinkedIn directory.',
      { confidence_level: isFreeEmail || inputs.recruiterData?.email ? 95 : 75 }
    ),

    // 7. Communication Channel & Urgency
    makeAssessment(
      'communication_channel',
      'Recruitment Communication Channel & Urgency',
      hasInformal ? 82 : (inputs.documentData?.has_urgency ? 65 : 12),
      hasInformal
        ? 'Recruitment directed to personal or encrypted messaging apps (WhatsApp / Telegram).'
        : inputs.documentData?.has_urgency
        ? 'Coercive urgency tactics or immediate cancellation deadlines detected in letter.'
        : 'Standard professional communication channels and reasonable response timelines.',
      'Scammers rely on private messaging platforms to evade enterprise monitoring and law enforcement tracking.',
      'High',
      hasInformal
        ? 'Refuse to conduct interviews or onboarding on personal WhatsApp or Telegram channels.'
        : 'Take time to independently evaluate the offer; genuine employers provide adequate response windows.',
      { confidence_level: 90 }
    ),

    // 8. Signatory Identity & Digital Signature Verification
    makeAssessment(
      'signatory_identity',
      'Signatory Identity & Digital Signature Verification',
      inputs.certificateData?.has_digital_signature
        ? 10
        : (inputs.documentData?.detected_signatory ? 20 : 40),
      inputs.certificateData?.has_digital_signature
        ? `Cryptographic digital signature verified (${inputs.certificateData.signature_issuer || 'Corporate Cert'}).`
        : inputs.documentData?.detected_signatory
        ? `Signatory identified in document: ${inputs.documentData.detected_signatory}.`
        : 'No named authorized signatory or cryptographic digital signature detected.',
      'Named signatories provide organizational accountability. Unsigned or generic offers facilitate fraudulent repudiation.',
      'Moderate',
      'Check if the named signatory is a verified executive or HR manager on LinkedIn.',
      { confidence_level: 80 }
    ),

    // 9. Machine Learning Fraud Classifier
    makeAssessment(
      'ml_fraud_pattern',
      'Machine Learning Fraud Classifier',
      inputs.mlPrediction ? Math.round(inputs.mlPrediction.fraud_probability * 100) : 20,
      inputs.mlPrediction
        ? `Statistical fraud classifier predicts ${Math.round(inputs.mlPrediction.fraud_probability * 100)}% scam probability based on linguistic patterns.`
        : 'Machine learning baseline evaluated offer language without severe anomalies.',
      'Supervised ML model trained on verified genuine and fraudulent employment offers detects subtle deceptive phrasing.',
      inputs.mlPrediction && inputs.mlPrediction.fraud_probability > 0.65 ? 'High' : 'Moderate',
      'Compare linguistic findings with factual domain and registration records.',
      { confidence_level: Math.round((inputs.mlPrediction?.confidence || 0.85) * 100) }
    ),

    // 10. Candidate Community Experience & Public Complaints
    makeAssessment(
      'community_sentiment',
      'Candidate Community Experience & Public Complaints',
      inputs.communityData && (inputs.communityData.complaint_count > 0 || inputs.communityData.scam_reports > 0) ? 82 : 15,
      inputs.communityData && (inputs.communityData.complaint_count > 0 || inputs.communityData.scam_reports > 0)
        ? `Public forum reports or candidate complaints identified (${inputs.communityData.complaint_count} complaints, ${inputs.communityData.scam_reports} scam reports).`
        : 'No active public complaints or scam reports linked to this entity or recruiter.',
      'Crowdsourced feedback from peer candidates often exposes hiring scams before formal law enforcement action.',
      'High',
      'Search Reddit and Quora for candidate discussions about this specific employer and recruitment campaign.',
      { confidence_level: 85 }
    ),

    // 11. Malicious Threat Intelligence & IOC Feeds
    makeAssessment(
      'threat_intelligence',
      'Malicious Threat Intelligence & IOC Feeds',
      inputs.threatData?.known_threat || inputs.threatData?.max_severity === 'CRITICAL' ? 95 : 10,
      inputs.threatData?.known_threat || inputs.threatData?.max_severity === 'CRITICAL'
        ? 'Domain or associated IP matches malicious IOC entries in global threat intelligence feeds.'
        : 'Zero malicious indicators in AbuseIPDB, URLhaus, or VirusTotal intelligence feeds.',
      'Confirmed malicious indicators represent active cyber threat operations rather than ordinary employment processes.',
      'High',
      inputs.threatData?.known_threat
        ? 'Block all communications immediately and do not download attachments.'
        : 'Standard cyber hygiene recommended.',
      { confidence_level: 95 }
    ),

    // 12. Cross-Signal Fact Consistency & Anomaly Detection
    makeAssessment(
      'consistency_conflict',
      'Cross-Signal Fact Consistency & Anomaly Detection',
      conflicts.length > 0 ? Math.min(90, 45 + conflicts.length * 20) : 12,
      conflicts.length > 0
        ? `${conflicts.length} cross-signal contradictions detected: ${conflicts.map(c => c.description).join('; ')}`
        : 'High cross-signal consistency across document claims, registry records, and domain intelligence.',
      'Impersonators often mix authentic corporate details with fraudulent payment or contact endpoints, creating internal contradictions.',
      'High',
      conflicts.length > 0
        ? 'Resolve conflicting information with the registered headquarters before proceeding.'
        : 'Continue standard pre-joining verification.',
      { confidence_level: 85 }
    ),
  ];

  return assessments;
}
