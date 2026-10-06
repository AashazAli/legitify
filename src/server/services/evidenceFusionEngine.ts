// ==============================================================================
// LEGITIFY EVIDENCE FUSION ENGINE
// Combines LEGITIFY forensic engine and Gemini independent investigation.
// 
// ARCHITECTURE:
//   LEGITIFY evidence (E-001..N)
//   + GEMINI evidence (GEM-E-001..N)
//   → deduplication
//   → corroboration detection
//   → conflict detection
//   → hard safety rules
//   → deterministic dynamic score
//   → final verdict
//
// CRITICAL RULES:
// 1. Gemini does NOT directly control the final score
// 2. Same underlying fact found by both engines = counted ONCE
// 3. Source failure ≠ negative evidence
// 4. All score changes must be traceable to evidence
// ==============================================================================

import {
  GeminiInvestigationResult,
  GeminiEvidence,
  EvidenceFusionResult,
  CorroboratedFact,
  EvidenceConflictV2,
  HardSafetyRule,
  DimensionScore,
  EvidenceAvailability,
  PublicExperienceResult,
  EntityGraphData,
  FraudPatternMatch,
  LegitimatePatternMatch,
  CounterEvidenceMatch,
} from '../../types/forensicTypes';
import { DeterministicScoreResult } from './scoringService';
import { EvidenceItem } from '../../types';

const FUSION_VERSION = 'LEGITIFY-FUSION-v2.0';

export interface FusionInput {
  /** LEGITIFY deterministic score result */
  legitifyResult: DeterministicScoreResult;
  /** All LEGITIFY evidence items */
  legitifyEvidence: EvidenceItem[];
  /** Gemini investigation result (may be unavailable) */
  geminiResult?: GeminiInvestigationResult;
  /** Flags from document analysis */
  hasFeeDemand: boolean;
  hasLookalikeDomain: boolean;
  hasKnownThreat: boolean;
  /** Context for conflict detection */
  companyName?: string;
  domain?: string;
  recruiterEmail?: string;
  /** Enhanced Detection Subsystems */
  publicExperience?: PublicExperienceResult;
  entityGraph?: EntityGraphData;
  fraudPatterns?: FraudPatternMatch[];
  legitimatePatterns?: LegitimatePatternMatch[];
  counterEvidence?: CounterEvidenceMatch[];
  isYoungStartup?: boolean;
}

/**
 * Main evidence fusion function.
 * 
 * This is the ONLY component allowed to produce the final score.
 * Gemini findings become structured evidence, processed deterministically.
 * 
 * DETERMINISTIC: same inputs → same fusion result.
 */
export function runEvidenceFusion(input: FusionInput): EvidenceFusionResult {
  const fusionTimestamp = new Date().toISOString();
  const hardRulesTriggered: HardSafetyRule[] = [];
  
  // ---- Step 1: Gather all evidence ----
  const geminiEvidence: GeminiEvidence[] = input.geminiResult?.evidence || [];
  const geminiAvailable = input.geminiResult?.investigationStatus === 'COMPLETED'
    || input.geminiResult?.investigationStatus === 'PARTIAL';

  // ---- Step 2: Deduplication + Corroboration ----
  // Find cases where both engines detected the same underlying fact
  const corroboratedFacts: CorroboratedFact[] = [];
  const uniqueLegitifyIds: string[] = [];
  const uniqueGeminiIds: string[] = [];

  // Map Gemini evidence findings to LEGITIFY evidence for overlap detection
  const processedGeminiIds = new Set<string>();

  for (const gemEv of geminiEvidence) {
    const finding = gemEv.finding.toLowerCase();
    
    // Check if LEGITIFY found the same underlying fact
    const matchingLegitify = findMatchingLegitifyEvidence(
      finding,
      gemEv.direction,
      input.legitifyEvidence
    );

    if (matchingLegitify) {
      // Same fact found by both — corroborated, NOT double-counted
      const factId = `FACT-${corroboratedFacts.length + 1}`;
      corroboratedFacts.push({
        factId,
        description: gemEv.finding,
        supportingEvidenceIds: [matchingLegitify, gemEv.evidenceId],
        isIndependent: false,  // Both derived from same document
        corroboration: true,
        effectiveWeight: 1.0,  // Count once, not twice
      });
      processedGeminiIds.add(gemEv.evidenceId);
    } else {
      // Unique Gemini finding — this is additional independent evidence
      if (!processedGeminiIds.has(gemEv.evidenceId)) {
        uniqueGeminiIds.push(gemEv.evidenceId);
        processedGeminiIds.add(gemEv.evidenceId);
      }
    }
  }

  // Track LEGITIFY evidence not corroborated by Gemini
  for (const ev of input.legitifyEvidence) {
    const evId = (ev as any).evidence_id || (ev as any).id || 'unknown';
    const corroborated = corroboratedFacts.some(f => f.supportingEvidenceIds.includes(evId));
    if (!corroborated) {
      uniqueLegitifyIds.push(evId);
    }
  }

  // ---- Step 3: Conflict Detection ----
  const conflicts: EvidenceConflictV2[] = detectConflicts(
    input.legitifyResult,
    input.geminiResult,
    input.companyName,
    input.domain
  );

  // ---- Step 4: Start with LEGITIFY's evidence-based score ----
  // CRITICAL: The base score comes from LEGITIFY's deterministic evidence engine
  let workingScore = input.legitifyResult.trust_score;
  
  // ---- Step 5: Apply unique Gemini evidence as score adjustments ----
  // Gemini findings contribute via evidence adjustments, NOT direct score override
  if (geminiAvailable && uniqueGeminiIds.length > 0) {
    const geminiAdjustment = calculateGeminiScoreAdjustment(
      input.geminiResult!,
      uniqueGeminiIds
    );
    const prevScore = workingScore;
    workingScore = Math.max(1, Math.min(99, workingScore + geminiAdjustment));
    
    if (Math.abs(geminiAdjustment) > 0.5) {
      // Log that Gemini unique evidence changed the score
      hardRulesTriggered.push({
        ruleId: 'GEMINI_UNIQUE_EVIDENCE',
        name: 'Gemini Independent Evidence Contribution',
        triggerCondition: `${uniqueGeminiIds.length} unique Gemini evidence items`,
        effect: `Score ${geminiAdjustment > 0 ? 'decreased' : 'increased'} by ${Math.abs(Math.round(geminiAdjustment))} points`,
        scoreBefore: prevScore,
        scoreAfter: workingScore,
        evidenceIds: uniqueGeminiIds,
      });
    }
  }

  // ---- Step 6: Hard Safety Rules (applied last, override everything) ----
  // These are the only rules that can override the evidence score direction
  
  if (input.hasFeeDemand) {
    const prevScore = workingScore;
    workingScore = Math.min(workingScore, 20);
    if (prevScore > 20) {
      hardRulesTriggered.push({
        ruleId: 'CONFIRMED_PAYMENT_REQUEST',
        name: 'Candidate Payment Demand Detected',
        triggerCondition: 'has_fee_demand = true (confirmed, not negated)',
        effect: 'Maximum trust score capped at 20',
        scoreCapApplied: 20,
        scoreBefore: prevScore,
        scoreAfter: workingScore,
        evidenceIds: input.legitifyEvidence
          .filter(e => e.evidence_type === 'FEE_DEMAND' || e.evidence_type === 'PAYMENT_REQUEST')
          .map((e, i) => (e as any).evidence_id || `E-FEE-${i + 1}`),
      });
    }
  }

  if (input.hasLookalikeDomain) {
    const prevScore = workingScore;
    workingScore = Math.min(workingScore, 25);
    if (prevScore > 25) {
      hardRulesTriggered.push({
        ruleId: 'HIGH_CONFIDENCE_LOOKALIKE_DOMAIN',
        name: 'Lookalike Domain Impersonation Detected',
        triggerCondition: 'lookalike_detected = true with HIGH_CONFIDENCE classification',
        effect: 'Maximum trust score capped at 25',
        scoreCapApplied: 25,
        scoreBefore: prevScore,
        scoreAfter: workingScore,
        evidenceIds: [],
      });
    }
  }

  if (input.hasKnownThreat) {
    const prevScore = workingScore;
    workingScore = Math.min(workingScore, 15);
    if (prevScore > 15) {
      hardRulesTriggered.push({
        ruleId: 'KNOWN_MALICIOUS_IOC',
        name: 'Known Malicious Threat Indicator Matched',
        triggerCondition: 'threat feed confirmed malicious match',
        effect: 'Maximum trust score capped at 15',
        scoreCapApplied: 15,
        scoreBefore: prevScore,
        scoreAfter: workingScore,
        evidenceIds: [],
      });
    }
  }

  // ---- Step 6.5: Evaluate Pattern Matches & Corroborated Clusters ----
  // A. Public Experience Official Advisory Corroboration
  if (input.publicExperience?.officialWarnings && input.publicExperience.officialWarnings.length > 0) {
    const warning = input.publicExperience.officialWarnings[0];
    corroboratedFacts.push({
      factId: `FACT-ADV-${corroboratedFacts.length + 1}`,
      description: `Official Corporate Warning: ${warning.title}`,
      supportingEvidenceIds: [warning.evidenceId],
      isIndependent: true,
      corroboration: true,
      effectiveWeight: 1.0,
    });
    if (input.hasLookalikeDomain || input.hasFeeDemand) {
      const prevScore = workingScore;
      workingScore = Math.min(workingScore, 12);
      hardRulesTriggered.push({
        ruleId: 'OFFICIAL_CORPORATE_WARNING_MATCH',
        name: 'Target Matches Official Company Fraud Advisory',
        triggerCondition: 'Official advisory confirmed from enterprise security roster',
        effect: 'Maximum trust score capped at 12',
        scoreCapApplied: 12,
        scoreBefore: prevScore,
        scoreAfter: workingScore,
        evidenceIds: [warning.evidenceId],
      });
    }
  }

  // B. Public Experience Complaint Clusters
  if (input.publicExperience?.clusters && input.publicExperience.clusters.length > 0) {
    const cluster = input.publicExperience.clusters[0];
    corroboratedFacts.push({
      factId: `FACT-CLUSTER-${corroboratedFacts.length + 1}`,
      description: `Public Experience Fraud Cluster: ${cluster.reportCount} independent reports corroborate recruitment fraud`,
      supportingEvidenceIds: cluster.matchedIndicators,
      isIndependent: true,
      corroboration: true,
      effectiveWeight: 1.0,
    });
    if (cluster.independentReports >= 3) {
      const prevScore = workingScore;
      workingScore = Math.min(workingScore, 20);
      if (prevScore > 20) {
        hardRulesTriggered.push({
          ruleId: 'PUBLIC_FRAUD_CLUSTER_CAP',
          name: 'Multi-Report Candidate Fraud Cluster Corroborated',
          triggerCondition: '3+ independent candidate reports reference matching indicators',
          effect: 'Maximum trust score capped at 20',
          scoreCapApplied: 20,
          scoreBefore: prevScore,
          scoreAfter: workingScore,
          evidenceIds: [],
        });
      }
    } else if (cluster.independentReports === 2) {
      const prevScore = workingScore;
      workingScore = Math.max(1, workingScore - 15);
      hardRulesTriggered.push({
        ruleId: 'CORROBORATED_REPORT_PENALTY',
        name: 'Two Independent Candidate Reports Corroborated',
        triggerCondition: '2 independent candidate reports reference matching anomalies',
        effect: 'Trust score reduced by 15 points (no hard cap)',
        scoreBefore: prevScore,
        scoreAfter: workingScore,
        evidenceIds: [],
      });
    }
  }

  // C. Counter-Evidence Evaluation (False-Positive Control)
  if (input.counterEvidence && input.counterEvidence.length > 0) {
    for (const ce of input.counterEvidence) {
      corroboratedFacts.push({
        factId: `FACT-COUNTER-${corroboratedFacts.length + 1}`,
        description: `Counter-Evidence: ${ce.counterEvidence}`,
        supportingEvidenceIds: [ce.signalId],
        isIndependent: true,
        corroboration: true,
        effectiveWeight: 0.8,
      });
    }
  }

  const isInsufficient = (input.legitifyResult.verdict === 'INSUFFICIENT_EVIDENCE' || input.legitifyResult.trust_score === 0)
    && !input.hasFeeDemand
    && !input.hasLookalikeDomain
    && !input.hasKnownThreat
    && uniqueGeminiIds.length === 0;

  const finalTrustScore = isInsufficient ? 0 : Math.round(Math.max(1, Math.min(99, workingScore)));

  // ---- Step 7: Calculate final evidence confidence ----
  const finalEvidenceConfidence = isInsufficient ? 0 : calculateFusedConfidence(
    input.legitifyResult.confidence_score,
    geminiAvailable,
    input.geminiResult?.confidence,
    corroboratedFacts.length,
    uniqueGeminiIds.length
  );

  // ---- Step 8: Determine final risk level and verdict ----
  let { riskLevel, verdict } = determineRiskLevelAndVerdict(finalTrustScore, isInsufficient);

  // False-positive override for early-stage startups with zero fee demand
  if (input.isYoungStartup && !input.hasFeeDemand && !input.hasLookalikeDomain && !input.hasKnownThreat) {
    if (finalTrustScore < 50 && finalTrustScore >= 20) {
      verdict = 'INSUFFICIENT EVIDENCE / REVIEW';
      riskLevel = 'MODERATE';
    }
  }

  // Calculate Fraud Confidence (0 - 100)
  let fraudConfidence = isInsufficient ? 0 : 10;
  if (input.hasFeeDemand || input.fraudPatterns?.some(p => p.patternId === 'FP001')) {
    fraudConfidence = Math.max(fraudConfidence, 96);
  }
  if (input.hasLookalikeDomain || input.fraudPatterns?.some(p => p.patternId === 'FP002')) {
    fraudConfidence = Math.max(fraudConfidence, 94);
  }
  if (input.hasKnownThreat) {
    fraudConfidence = Math.max(fraudConfidence, 98);
  }
  if (input.legitimatePatterns?.some(p => p.patternId === 'LP001') && !input.hasFeeDemand) {
    fraudConfidence = Math.min(fraudConfidence, 15);
  }

  // ---- Step 9: Build 10-dimension breakdown ----
  const finalDimensions = buildFinalDimensions(input.legitifyResult);

  // ---- Step 10: Build Transparent Explanation Summary ----
  const whatWeFound: string[] = [];
  const whyItMatters: string[] = [];
  const whatIsVerified: string[] = [];
  const whatIsSuspicious: string[] = [];
  const whatShouldBeDone: string[] = [];

  if (input.hasFeeDemand) {
    whatWeFound.push('Document contains an explicit candidate payment demand or registration fee requirement.');
    whyItMatters.push('Legitimate employers never demand payment, registration charges, or equipment deposits from candidates.');
    whatIsSuspicious.push('Mandatory upfront fee condition detected.');
    whatShouldBeDone.push('🚨 DO NOT PAY. Cease all financial transactions immediately.');
  }

  if (input.hasLookalikeDomain) {
    whatWeFound.push('Communication domain exhibits brand impersonation / typosquatting characteristics.');
    whyItMatters.push('Lookalike domains are designed to deceive applicants into believing they are contacting official corporate teams.');
    whatIsSuspicious.push('Domain structure mimics established corporate brand.');
    whatShouldBeDone.push('Verify recruiter authorization through the company official corporate careers switchboard.');
  }

  if (input.publicExperience?.officialWarnings && input.publicExperience.officialWarnings.length > 0) {
    whatWeFound.push(`Target entity matches official corporate security advisory: "${input.publicExperience.officialWarnings[0].title}".`);
    whyItMatters.push('Official corporate alerts confirm active impersonation campaigns targeting applicants.');
  }

  if (input.legitimatePatterns && input.legitimatePatterns.length > 0) {
    for (const lp of input.legitimatePatterns) {
      whatIsVerified.push(`${lp.name}: ${lp.description}`);
    }
  }

  if (whatShouldBeDone.length === 0) {
    whatShouldBeDone.push('Review corporate registration and cross-verify recruiter email before sharing personal identity documents.');
  }

  return {
    legitifyTrustScore: input.legitifyResult.trust_score,
    legitifyConfidence: input.legitifyResult.confidence_score,
    geminiStatus: input.geminiResult?.investigationStatus || 'NOT_CONFIGURED',
    corroboratedFacts,
    uniqueLegitifyEvidenceIds: uniqueLegitifyIds,
    uniqueGeminiEvidenceIds: uniqueGeminiIds,
    conflicts,
    hardRulesTriggered,
    finalDimensions,
    finalTrustScore,
    finalEvidenceConfidence,
    fraudConfidence,
    finalRiskLevel: riskLevel as any,
    finalVerdict: verdict,
    scoringModelVersion: FUSION_VERSION,
    fusionTimestamp,
    fraudPatterns: input.fraudPatterns,
    legitimatePatterns: input.legitimatePatterns,
    counterEvidence: input.counterEvidence,
    publicExperience: input.publicExperience,
    entityGraph: input.entityGraph,
    explanationSummary: {
      whatWeFound,
      whyItMatters,
      whatIsVerified,
      whatIsSuspicious,
      whatShouldBeDone,
    },
  };
}

/**
 * Find if a Gemini finding matches an existing LEGITIFY evidence item.
 * Used for deduplication — prevents double-counting the same underlying fact.
 */
function findMatchingLegitifyEvidence(
  geminiFindinglc: string,
  direction: string,
  legitifyEvidence: EvidenceItem[]
): string | null {
  // Keywords that indicate the same underlying fact
  const PAYMENT_KEYWORDS = ['payment', 'fee', 'deposit', 'charge', 'upi', 'transfer'];
  const WEBMAIL_KEYWORDS = ['gmail', 'yahoo', 'free webmail', 'free email', 'public webmail'];
  const LOOKALIKE_KEYWORDS = ['lookalike', 'typosquat', 'impersonat', 'fake domain'];
  const COMPANY_KEYWORDS = ['registered', 'registration', 'mca', 'cin', 'company exist'];

  const geminiHasPayment = PAYMENT_KEYWORDS.some(k => geminiFindinglc.includes(k));
  const geminiHasWebmail = WEBMAIL_KEYWORDS.some(k => geminiFindinglc.includes(k));
  const geminiHasLookalike = LOOKALIKE_KEYWORDS.some(k => geminiFindinglc.includes(k));
  const geminiHasCompany = COMPANY_KEYWORDS.some(k => geminiFindinglc.includes(k));

  for (const ev of legitifyEvidence) {
    const evType = (ev.evidence_type || '').toLowerCase();
    const evText = (ev.evidence_text || ev.snippet || '').toLowerCase();

    // Match payment signals
    if (geminiHasPayment && (evType.includes('fee') || evType.includes('payment') || evText.includes('fee'))) {
      return (ev as any).evidence_id || ev.evidence_type || 'matched';
    }

    // Match webmail signals
    if (geminiHasWebmail && (evType.includes('webmail') || evType.includes('free_email'))) {
      return (ev as any).evidence_id || ev.evidence_type || 'matched';
    }

    // Match lookalike signals
    if (geminiHasLookalike && (evType.includes('lookalike') || evType.includes('typosquat'))) {
      return (ev as any).evidence_id || ev.evidence_type || 'matched';
    }

    // Match company signals
    if (geminiHasCompany && (evType.includes('registry') || evType.includes('mca') || evType.includes('cin'))) {
      return (ev as any).evidence_id || ev.evidence_type || 'matched';
    }
  }

  return null;
}

/**
 * Calculate Gemini's score adjustment based on UNIQUE evidence.
 * NEVER averages Gemini score with LEGITIFY score directly.
 * Each unique finding contributes a small, bounded adjustment.
 */
function calculateGeminiScoreAdjustment(
  geminiResult: GeminiInvestigationResult,
  uniqueGeminiIds: string[]
): number {
  if (uniqueGeminiIds.length === 0) return 0;

  let adjustment = 0;

  // Only count evidence in uniqueGeminiIds
  const uniqueEvidence = geminiResult.evidence.filter(e => uniqueGeminiIds.includes(e.evidenceId));

  for (const ev of uniqueEvidence) {
    const strengthFactor = ev.strength;

    if (ev.direction === 'RISK') {
      // Risk evidence pushes score DOWN (bounded at -8 per evidence item)
      adjustment -= Math.min(8, strengthFactor * 10);
    } else if (ev.direction === 'LEGITIMACY') {
      // Legitimacy evidence pushes score UP (bounded at +5 per evidence item)
      adjustment += Math.min(5, strengthFactor * 7);
    }
  }

  // Total Gemini adjustment bounded at ±20 to prevent overriding LEGITIFY evidence
  return Math.max(-20, Math.min(20, Math.round(adjustment)));
}

/**
 * Detect conflicts between LEGITIFY and Gemini assessments.
 */
function detectConflicts(
  legitifyResult: DeterministicScoreResult,
  geminiResult?: GeminiInvestigationResult,
  companyName?: string,
  domain?: string
): EvidenceConflictV2[] {
  const conflicts: EvidenceConflictV2[] = [];

  if (!geminiResult || geminiResult.investigationStatus !== 'COMPLETED') {
    return conflicts;
  }

  // Check for engine-level disagreement
  const legitifyHighRisk = legitifyResult.trust_score < 40;
  const geminiHighRisk = geminiResult.verdict === 'HIGH_RISK';
  const geminiLowRisk = geminiResult.verdict === 'LOW_RISK';

  if (legitifyHighRisk && geminiLowRisk) {
    conflicts.push({
      conflictId: 'CONFLICT-001',
      type: 'ML_VS_EVIDENCE_CONFLICT',
      severity: 'HIGH',
      description: `LEGITIFY forensic engine indicates HIGH RISK (score: ${legitifyResult.trust_score}) while Gemini investigation assessment is LOW RISK. Review conflicting evidence.`,
      source1: { id: 'LEGITIFY', value: `Trust Score: ${legitifyResult.trust_score}`, source: 'LEGITIFY Forensic Engine' },
      source2: { id: 'GEMINI', value: `Verdict: ${geminiResult.verdict}`, source: 'Gemini Independent Investigation' },
      resolution: 'Hard safety rules take precedence over Gemini assessment when confirmed evidence exists.',
    });
  }

  return conflicts;
}

/**
 * Calculate fused evidence confidence.
 * Higher confidence when both engines agree AND have corroborated findings.
 */
function calculateFusedConfidence(
  legitifyConfidence: number,
  geminiAvailable: boolean,
  geminiConfidence?: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN',
  corroboratedCount?: number,
  uniqueGeminiCount?: number
): number {
  let confidence = legitifyConfidence;

  if (geminiAvailable) {
    const gemConf = geminiConfidence === 'HIGH' ? 10
      : geminiConfidence === 'MEDIUM' ? 5
      : geminiConfidence === 'LOW' ? -5
      : 0;

    // Corroboration increases confidence
    const corrobBonus = Math.min(10, (corroboratedCount || 0) * 2);
    
    // Unique Gemini evidence increases coverage
    const uniqueBonus = Math.min(5, (uniqueGeminiCount || 0) * 1);

    confidence = Math.min(98, confidence + gemConf + corrobBonus + uniqueBonus);
  }

  return Math.round(Math.max(10, Math.min(98, confidence)));
}

/**
 * Determine risk level and verdict from final trust score.
 * DETERMINISTIC: same score → same verdict.
 */
function determineRiskLevelAndVerdict(trustScore: number, isInsufficient = false): {
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  verdict: string;
} {
  if (isInsufficient || trustScore === 0) {
    return { riskLevel: 'MODERATE', verdict: 'INSUFFICIENT EVIDENCE / REVIEW' };
  }
  if (trustScore >= 80) return { riskLevel: 'LOW', verdict: 'LIKELY LEGITIMATE' };
  if (trustScore >= 65) return { riskLevel: 'LOW', verdict: 'LOW RISK' };
  if (trustScore >= 45) return { riskLevel: 'MODERATE', verdict: 'MODERATE RISK' };
  if (trustScore >= 28) return { riskLevel: 'HIGH', verdict: 'HIGH RISK' };
  return { riskLevel: 'CRITICAL', verdict: 'LIKELY SCAM' };
}

/**
 * Build the 10-dimension breakdown from LEGITIFY result.
 */
function buildFinalDimensions(legitifyResult: DeterministicScoreResult): DimensionScore[] {
  const components = legitifyResult.components as any;
  
  const dimensions: DimensionScore[] = [];

  function addDim(key: string, dim: string, name: string): void {
    const comp = components?.[key];
    if (!comp) return;
    dimensions.push({
      dimension: dim,
      name,
      weight: comp.weight || 0,
      score: comp.score || 0,
      weighted_score: comp.weighted_score || 0,
      confidence: comp.confidence || 0,
      availability: 'LIVE_VERIFIED' as EvidenceAvailability,
      reason: comp.reason || '',
      evidence_ids: [],
      positive_signals: [],
      negative_signals: [],
    });
  }

  addDim('document_authenticity', 'document_authenticity', 'Document Authenticity');
  addDim('ml_probability', 'ml_fraud_model', 'ML Fraud Model');
  addDim('company', 'company_verification', 'Company Legal Verification');
  addDim('domain', 'domain_security', 'Domain Security');
  addDim('recruiter', 'recruiter_authentication', 'Recruiter Authentication');
  addDim('document', 'financial_safety', 'Financial / Fee Safety');
  addDim('certificate', 'certificate_verification', 'Certificate Verification');
  addDim('threat', 'threat_intelligence', 'Threat Intelligence');
  addDim('community', 'community_evidence', 'Community Evidence');
  addDim('consistency', 'cross_source_consistency', 'Cross-Source Consistency');

  return dimensions;
}
