// ==============================================================================
// LEGITIFY FORENSIC TYPES
// Shared types for the evidence-first forensic intelligence system
// Version: 2.0 — Deterministic Dynamic Architecture
// ==============================================================================

/**
 * Availability states for evidence sources.
 * CRITICAL: Source failure must NEVER become negative evidence.
 */
export type EvidenceAvailability =
  | 'LIVE_VERIFIED'      // Real-time external source confirmed fact
  | 'CACHED_VERIFIED'    // Verified within cache TTL
  | 'LOCAL_REFERENCE'    // From hardcoded local dataset, NOT live external
  | 'KEYWORD_MATCH'      // RAG keyword/rule match (NOT semantic embedding)
  | 'UNVERIFIED'         // Could not be checked
  | 'NOT_FOUND'          // Checked, no match found
  | 'SOURCE_UNAVAILABLE' // Service/API not configured or timed out
  | 'FAILED'             // Error during check
  | 'NOT_APPLICABLE';    // Dimension not relevant to this scan type

/**
 * Service status states for health reporting.
 */
export type ServiceStatus =
  | 'READY'
  | 'DEGRADED'
  | 'UNAVAILABLE'
  | 'DISABLED'
  | 'LOCAL_REFERENCE_ONLY'
  | 'ERROR';

/**
 * RAG retrieval method — must be explicit.
 * KEYWORD_RULE: score-based keyword/rule matching (current)
 * VECTOR_SEMANTIC: real embedding similarity (future)
 */
export type RAGMatchMethod = 'KEYWORD_RULE' | 'VECTOR_SEMANTIC';

/**
 * Registry source type — must never misrepresent local data as live.
 */
export type RegistrySourceType =
  | 'LIVE_MCA21'         // Real-time Ministry of Corporate Affairs API
  | 'LOCAL_REFERENCE'    // Hardcoded local reference dataset
  | 'CACHED_MCA21';      // Cached from a previous live query

/**
 * Evidence direction: does this evidence support risk or legitimacy?
 */
export type EvidenceDirection = 'RISK' | 'LEGITIMACY' | 'NEUTRAL' | 'UNKNOWN';

/**
 * Dimension score for a single scoring dimension.
 * All values are derived from actual evidence, never hardcoded.
 */
export interface DimensionScore {
  /** Dimension identifier */
  dimension: string;
  /** Human-readable name */
  name: string;
  /** Weight in overall score (0-1, all weights sum to 1.0) */
  weight: number;
  /** Normalized dimension score (0-100) */
  score: number;
  /** Weighted contribution to final score */
  weighted_score: number;
  /** Confidence in this dimension's score (0-100) */
  confidence: number;
  /** Availability status of evidence for this dimension */
  availability: EvidenceAvailability;
  /** Human-readable explanation */
  reason: string;
  /** IDs of evidence items driving this score */
  evidence_ids: string[];
  /** Signals that raised this score */
  positive_signals: string[];
  /** Signals that lowered this score */
  negative_signals: string[];
}

/**
 * A document chunk — semantic unit extracted from a document.
 */
export interface DocumentChunk {
  /** Unique chunk ID, e.g. CHK-001 */
  chunkId: string;
  /** Parent document ID */
  documentId: string;
  /** Page where chunk starts */
  pageStart: number;
  /** Page where chunk ends */
  pageEnd: number;
  /** Extracted text content */
  text: string;
  /** Semantic section type */
  section: DocumentSection;
  /** Character length */
  charCount: number;
  /** SHA-256 hash of chunk text */
  hash: string;
  /** Extraction confidence (0-1) */
  confidence: number;
}

export type DocumentSection =
  | 'LETTERHEAD'
  | 'ORGANIZATION_DETAILS'
  | 'EMPLOYMENT_TERMS'
  | 'COMPENSATION'
  | 'JOINING_INFORMATION'
  | 'PAYMENT_TERMS'
  | 'CONTACT_INFORMATION'
  | 'SIGNATURE'
  | 'LEGAL_CLAUSES'
  | 'HEADER'
  | 'FOOTER'
  | 'BODY'
  | 'UNKNOWN';

/**
 * A structured claim extracted from a document chunk.
 */
export interface ForensicClaim {
  /** Unique claim ID, e.g. CLM-001 */
  claimId: string;
  /** Source chunk ID */
  chunkId: string;
  /** Page number where claim appears */
  page: number;
  /** Type of claim */
  type: ClaimType;
  /** Raw text from which claim was extracted */
  rawText: string;
  /** Normalized/cleaned value */
  normalizedValue: string;
  /** Extraction confidence (0-1) */
  extractionConfidence: number;
  /** Verification result */
  verification: ClaimVerification;
}

export type ClaimType =
  | 'ORGANIZATION'
  | 'RECRUITER_EMAIL'
  | 'RECRUITER_NAME'
  | 'PHONE_NUMBER'
  | 'WEBSITE_URL'
  | 'COMPANY_DOMAIN'
  | 'CIN_NUMBER'
  | 'ROLE_TITLE'
  | 'STIPEND'
  | 'SALARY'
  | 'JOINING_DATE'
  | 'LOCATION'
  | 'PAYMENT_REQUEST'
  | 'PAYMENT_AMOUNT'
  | 'PAYMENT_METHOD'
  | 'UPI_ID'
  | 'BANK_ACCOUNT'
  | 'CERTIFICATE_ID'
  | 'SIGNATORY_NAME'
  | 'SIGNATORY_TITLE'
  | 'OFFER_SELECTION_CLAIM'
  | 'LOGO_IDENTITY_CLAIM'
  | 'TIMELINE_URGENCY_CLAIM'
  | 'FORMATTING_ANOMALY';

export interface ClaimVerification {
  status: 'VERIFIED' | 'CORROBORATED' | 'OBSERVED' | 'CONTRADICTED' | 'SUSPICIOUS' | 'UNVERIFIED' | 'NOT_FOUND' | 'NOT_APPLICABLE';
  checks: VerificationCheck[];
  evidenceIds: string[];
  notes?: string;
}

export interface VerificationCheck {
  name: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL' | 'UNAVAILABLE';
  source?: string;
  finding?: string;
}

/**
 * A structured evidence item with full provenance.
 */
export interface ForensicEvidence {
  /** Unique evidence ID, e.g. E-001 */
  evidenceId: string;
  /** Type of evidence */
  type: EvidenceType;
  /** Source of this evidence */
  source: EvidenceSource;
  /** Direction: does this support risk or legitimacy? */
  direction: EvidenceDirection;
  /** Raw strength of this evidence (0-1) */
  strength: number;
  /** Reliability of the source (0-1) */
  reliability: number;
  /** Source authority (0-1, higher = more authoritative) */
  authority: number;
  /** Freshness of the information (0-1) */
  freshness: number;
  /** Effective contribution = strength * reliability * authority * freshness */
  effectiveContribution: number;
  /** Human-readable finding */
  finding: string;
  /** Detailed explanation */
  explanation: string;
  /** Availability status */
  availability: EvidenceAvailability;
  /** When this evidence was retrieved */
  retrievedAt: string;
  /** Claim IDs this evidence supports or contradicts */
  relatedClaimIds: string[];
  /** Dimension this evidence contributes to */
  dimension: string;
}

export type EvidenceType =
  | 'DOCUMENT_TEXT'
  | 'DOCUMENT_VISUAL'
  | 'OCR_EXTRACTION'
  | 'REGISTRY_LOOKUP'
  | 'DNS_RESOLUTION'
  | 'RDAP_LOOKUP'
  | 'TLS_INSPECTION'
  | 'EMAIL_ANALYSIS'
  | 'THREAT_FEED'
  | 'COMMUNITY_REPORT'
  | 'ML_PREDICTION'
  | 'RAG_RETRIEVAL'
  | 'CROSS_SOURCE_CONFLICT'
  | 'GEMINI_INVESTIGATION';

export interface EvidenceSource {
  /** Source name */
  name: string;
  /** Source URL if applicable */
  url?: string;
  /** Authority tier */
  tier: 1 | 2 | 3 | 4;
  /** Retrieval method */
  method: 'LIVE_API' | 'LOCAL_RULE' | 'KEYWORD_MATCH' | 'ML_MODEL' | 'LLM_ANALYSIS';
}

export interface GeminiStructuredDossier {
  whatLegitifyFound: string[];
  whatGeminiFound: string[];
  agreements: string[];
  contradictions: string[];
  unknowns: string[];
  finalAssessment: string;
}

/**
 * Gemini independent investigation result.
 * Gemini is an independent investigator — NOT a scoring oracle.
 */
export interface GeminiInvestigationResult {
  engine: 'GEMINI';
  geminiModel: string;
  investigationStatus: GeminiInvestigationStatus;
  investigationTimestamp: string;
  verdict?: string;
  riskLevel?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  summary: string;
  positiveSignals: GeminiSignal[];
  riskSignals: GeminiSignal[];
  sources: GeminiSource[];
  unverifiedItems: string[];
  contradictions: string[];
  recommendedActions: string[];
  searchCoverage: {
    searchPerformed: boolean;
    queriesAttempted: string[];
    sourcesExamined: number;
    authoritativeSourcesFound: number;
    reason?: string;
  };
  evidence: GeminiEvidence[];
  structuredDossier?: GeminiStructuredDossier;
}

export type GeminiInvestigationStatus =
  | 'COMPLETED'
  | 'PARTIAL'
  | 'TIMEOUT'
  | 'RATE_LIMITED'
  | 'INVALID_RESPONSE'
  | 'NOT_CONFIGURED'
  | 'ERROR';

export interface GeminiSignal {
  finding: string;
  sourceId?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  evidenceId: string;
}

export interface GeminiSource {
  sourceId: string;
  title: string;
  publisher: string;
  url?: string;
  publishedDate?: string;
  retrievedAt: string;
  authorityTier: 1 | 2 | 3 | 4;
  finding: string;
  verified: boolean;
}

export interface GeminiEvidence {
  evidenceId: string;  // GEM-E-001 format
  type: string;
  sourceId?: string;
  direction: EvidenceDirection;
  strength: number;
  finding: string;
  isUniqueToGemini: boolean;  // true if LEGITIFY did NOT find same fact
  claim_state?: 'OBSERVED_BY_AI';
  source_tier?: 3;
  source_reliability?: number;
}

/**
 * Hard safety rule that was triggered.
 */
export interface HardSafetyRule {
  ruleId: string;
  name: string;
  triggerCondition: string;
  effect: string;
  scoreCapApplied?: number;
  scoreBefore: number;
  scoreAfter: number;
  evidenceIds: string[];
}

/**
 * Evidence conflict between two sources.
 */
export interface EvidenceConflictV2 {
  conflictId: string;
  type: ConflictType;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  source1: { id: string; value: string; source: string; };
  source2: { id: string; value: string; source: string; };
  resolution?: string;
}

export type ConflictType =
  | 'COMPANY_NAME_MISMATCH'
  | 'DOMAIN_MISMATCH'
  | 'EMAIL_DOMAIN_MISMATCH'
  | 'RECRUITER_IDENTITY_MISMATCH'
  | 'ADDRESS_MISMATCH'
  | 'DATE_MISMATCH'
  | 'STIPEND_MISMATCH'
  | 'REGISTRY_CONFLICT'
  | 'ML_VS_EVIDENCE_CONFLICT';

/**
 * Corroborated fact — same underlying fact found by multiple sources.
 * PREVENTS double-counting in evidence fusion.
 */
export interface CorroboratedFact {
  factId: string;
  description: string;
  supportingEvidenceIds: string[];  // E-001, GEM-E-004, etc.
  isIndependent: boolean;  // Were these truly independent sources?
  corroboration: boolean;
  effectiveWeight: number;  // Weight to assign (not double-counted)
}

/**
 * Complete fusion result from both LEGITIFY and Gemini engines.
 */
export interface EvidenceFusionResult {
  legitifyTrustScore: number;
  legitifyConfidence: number;
  geminiStatus: GeminiInvestigationStatus;
  corroboratedFacts: CorroboratedFact[];
  uniqueLegitifyEvidenceIds: string[];
  uniqueGeminiEvidenceIds: string[];
  conflicts: EvidenceConflictV2[];
  hardRulesTriggered: HardSafetyRule[];
  finalDimensions: DimensionScore[];
  finalTrustScore: number;
  finalEvidenceConfidence: number;
  fraudConfidence: number;
  finalRiskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | 'INSUFFICIENT EVIDENCE';
  finalVerdict: string;
  scoringModelVersion: string;
  fusionTimestamp: string;
  fraudPatterns?: FraudPatternMatch[];
  legitimatePatterns?: LegitimatePatternMatch[];
  counterEvidence?: CounterEvidenceMatch[];
  publicExperience?: PublicExperienceResult;
  entityGraph?: ForensicEntityGraph | any;
  explanationSummary?: {
    whatWeFound: string[];
    whyItMatters: string[];
    whatIsVerified: string[];
    whatIsSuspicious: string[];
    whatShouldBeDone: string[];
  };
}

// ==============================================================================
// PUBLIC EXPERIENCE & COMMUNITY INTELLIGENCE TYPES
// Mandatory Real-Source Integrity: Zero fabricated or inferred complaints.
// ==============================================================================

export type PublicSourceType =
  | 'REDDIT'
  | 'FORUM'
  | 'NEWS'
  | 'BLOG'
  | 'SEARCH_RESULT'
  | 'OFFICIAL_ADVISORY'
  | 'LINKEDIN_PUBLIC'
  | 'PROFESSIONAL_PLATFORM';

export type PublicExperienceType =
  | 'PAYMENT_SCAM_REPORT'
  | 'FAKE_OFFER_REPORT'
  | 'IMPERSONATION_REPORT'
  | 'INTERNSHIP_SCAM_REPORT'
  | 'RECRUITMENT_COMPLAINT'
  | 'WORKPLACE_COMPLAINT'
  | 'SALARY_COMPLAINT'
  | 'INTERVIEW_COMPLAINT'
  | 'POSITIVE_EXPERIENCE'
  | 'OFFICIAL_WARNING'
  | 'UNVERIFIED_USER_REPORT'
  | 'CORROBORATED_USER_REPORT'
  | 'OBSERVED_CLUSTER'
  | 'UNCERTAIN';

export type PublicSourceStatus =
  | 'LIVE'
  | 'CACHED'
  | 'STALE'
  | 'NOT_FOUND'
  | 'SOURCE_UNAVAILABLE'
  | 'FAILED';

export interface PublicExperience {
  id: string;
  sourceType: PublicSourceType;
  title: string;
  url: string;
  publisher: string | null;
  author: string | null;
  publishedAt: string | null;
  retrievedAt: string;
  recency: 'RECENT' | 'OLDER' | 'HISTORICAL' | 'UNKNOWN_DATE';
  matchedEntities: string[];
  experienceType: PublicExperienceType;
  relevance: number;      // 0.0 - 1.0 based on exact entity matching
  specificity: number;    // 0.0 - 1.0 based on payment/role/contact detail
  evidenceText: string;
  sourceTier: 'TIER_1' | 'TIER_2' | 'TIER_3' | 'TIER_4';
  credibility: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  evidenceId: string;
  isDuplicate?: boolean;
  primarySourceUrl?: string;
  status: PublicSourceStatus;
  matchRationale?: string;
}

export interface ComplaintCluster {
  clusterId: string;
  name: string;
  description: string;
  reportCount: number;
  independentReports: number;
  sharedRecruiter: boolean;
  sharedDomain: boolean;
  sharedUPI: boolean;
  sharedPaymentPattern: boolean;
  matchedIndicators: string[];
  sampleReports: { title: string; url: string; publishedAt: string | null; snippet: string }[];
  confidence: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface QueryAuditRecord {
  queryId: string;
  query: string;
  provider: string;
  executedAt: string;
  status: 'COMPLETED' | 'FAILED' | 'SKIPPED' | 'RATE_LIMITED';
  resultCount: number;
  targetEntity: string;
}

export interface ProviderStatusRecord {
  provider: string;
  status: PublicSourceStatus;
  lastChecked: string;
  notes?: string;
}

export interface PublicExperienceResult {
  investigationId: string;
  status: 'COMPLETED' | 'PARTIAL' | 'SOURCE_UNAVAILABLE' | 'FAILED';
  isLive: boolean;
  isCached: boolean;
  searchedAt: string;
  entitiesInvestigated: {
    company?: string;
    domain?: string;
    email?: string;
    phone?: string;
    upi?: string;
    role?: string;
  };
  queriesExecuted: QueryAuditRecord[];
  providers: ProviderStatusRecord[];
  sources: PublicExperience[];
  experienceSummary: {
    totalEvaluated: number;
    positive: number;
    cautionary: number;
    fraudRelated: number;
    uncertain: number;
  };
  clusters: ComplaintCluster[];
  officialWarnings: PublicExperience[];
  counterEvidence: PublicExperience[];
  limitations: string[];
}

// ==============================================================================
// ENTITY RELATIONSHIP GRAPH TYPES
// ==============================================================================

export type EntityNodeType =
  | 'COMPANY'
  | 'RECRUITER'
  | 'DOMAIN'
  | 'OFFER'
  | 'PAYMENT'
  | 'SIGNATORY';

export interface EntityGraphNode {
  id: string;
  type: EntityNodeType;
  label: string;
  attributes: Record<string, any>;
  verified: boolean;
  confidence: number;
}

export interface EntityGraphEdge {
  id: string;
  sourceId: string;
  targetId: string;
  relationship:
    | 'CLAIMS_COMPANY'
    | 'SENDER_EMAIL'
    | 'LISTED_DOMAIN'
    | 'OFFICIAL_DOMAIN'
    | 'RECRUITER_DOMAIN'
    | 'DEMANDS_PAYMENT'
    | 'SIGNED_BY'
    | 'PARENT_ORGANIZATION';
  status: 'VERIFIED' | 'CONTRADICTED' | 'UNVERIFIED' | 'SUSPICIOUS';
  evidenceIds: string[];
}

export interface GraphAnomaly {
  id: string;
  anomalyType:
    | 'DOMAIN_MISMATCH'
    | 'ENTERPRISE_ON_FREE_MAILBOX'
    | 'COMPENSATION_CONTRADICTION'
    | 'TEMPORAL_SEQUENCE_VIOLATION'
    | 'UNVERIFIED_SIGNATORY'
    | 'UNOFFICIAL_CAREER_URL';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  involvedNodes: string[];
  resolution?: string;
}

export interface ForensicEntityGraph {
  nodes: import('./index').GraphNode[];
  edges: import('./index').GraphEdge[];
  anomalies: GraphAnomaly[];
  coherenceScore: number; // 0 - 100
}

export type EntityGraphData = ForensicEntityGraph;

// ==============================================================================
// FRAUD & LEGITIMATE PATTERN TYPES
// ==============================================================================

export interface FraudPatternMatch {
  patternId: 'FP001' | 'FP002' | 'FP003' | 'FP004' | 'FP005' | 'FP006';
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  confidence: number; // 0 - 100
  matchedSignals: string[];
  evidenceIds: string[];
  explanation: string;
}

export interface LegitimatePatternMatch {
  patternId: 'LP001' | 'LP002' | 'LP003' | 'LP004' | 'LP005';
  name: string;
  description: string;
  strength: 'STRONG' | 'MODERATE';
  confidence: number; // 0 - 100
  matchedSignals: string[];
  evidenceIds: string[];
  explanation: string;
}

export interface CounterEvidenceMatch {
  signalId: string;
  originalRiskSignal: string;
  counterEvidence: string;
  source: string;
  authorityTier: 'TIER_1' | 'TIER_2' | 'TIER_3' | 'TIER_4';
  mitigationEffect: string;
}
