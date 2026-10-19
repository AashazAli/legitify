export type VisualSignatureType =
  | 'VISUAL_SIGNATURE'      // Something that looks like a signature (visual analysis only)
  | 'HANDWRITTEN_SIGNATURE'  // Appears handwritten (visual analysis only)
  | 'PRINTED_SIGNATURE'      // Printed name in signature position
  | 'STAMP'                  // Rubber stamp or similar
  | 'CRYPTOGRAPHIC_SIGNATURE' // ONLY when PDF digital signature metadata validates
  | 'ABSENT';                // No signature detected

export type SignatoryVerificationState =
  | 'NO_SIGNATURE_DETECTED'
  | 'SIGNATURE_PRESENT_UNIDENTIFIED'
  | 'SIGNATORY_OBSERVED'
  | 'SIGNATORY_CORROBORATED'
  | 'SIGNATORY_VERIFIED'
  | 'SIGNATORY_CONTRADICTED';

export type VisualRegionType =
  | 'SIGNATURE' | 'STAMP' | 'SEAL' | 'LOGO' | 'LETTERHEAD'
  | 'QR_CODE' | 'PHOTO' | 'TABLE' | 'HANDWRITING'
  | 'DIGITAL_SIGNATURE' | 'SIGNATORY_BLOCK';

export interface VisualRegion {
  type: VisualRegionType;
  page: number;
  boundingBox?: { x: number; y: number; width: number; height: number };
  confidence: number;
  nearbyText?: string;
  evidenceId: string;
  detectionMethod: 'GEMINI_VISION' | 'OCR_LAYOUT' | 'TEXT_PATTERN';
}

export interface VisualForensicsData {
  signature_detected: boolean;
  signature_type: VisualSignatureType;
  signatory_name?: string;
  signatory_title?: string;
  signatory_department?: string;
  signatory_state: SignatoryVerificationState;
  official_seal_detected: boolean;
  letterhead_logo_detected: boolean;
  font_consistency_score: number;
  formatting_anomalies: string[];
  visual_regions: VisualRegion[];
  evidence_ids: string[];
}

export interface DocumentClaim {
  id: string;
  claim_type: "ORGANIZATION" | "RECRUITER" | "CONTACT_EMAIL" | "PHONE" | "WEBSITE_DOMAIN" | "CIN_REGISTRATION" | "ROLE_DESIGNATION" | "STIPEND_COMPENSATION" | "JOINING_DATE" | "LOCATION" | "PAYMENT_REQUIREMENT" | "CERTIFICATE_ID" | "QR_CODE" | "AUTHENTICITY_SIGNAL";
  raw_claim_text: string;
  normalized_value: string;
  confidence: number; // 0 - 100
  page?: number;
  location?: string;
  verification_status: "VERIFIED" | "CONTRADICTED" | "UNVERIFIED" | "SUSPICIOUS" | "NOT_APPLICABLE";
  retrieved_reality?: string;
  evidence_source?: string;
  evidence_ids?: string[];
  explanation: string;
}

export interface RAGKnowledgeChunk {
  document_id: string;
  chunk_id: string;
  title: string;
  content: string;
  source: string;
  source_type: "GOVERNMENT_REGISTRY" | "COMPANY_CAREERS" | "CYBERCRIME_ADVISORY" | "SECURITY_DATABASE" | "COMMUNITY_FEED" | "DOCUMENT_UPLOAD";
  source_url?: string;
  publication_date?: string;
  authority_level: "TIER_1_AUTHORITATIVE" | "TIER_2_HIGH_QUALITY" | "TIER_3_COMMUNITY";
  similarity_score?: number;
  match_score?: number;
  match_method?: "KEYWORD_RULE" | "VECTOR_SEMANTIC";
  metadata?: Record<string, any>;
}

export interface FalsePositiveCheckResult {
  is_checked: boolean;
  legitimate_counter_evidence: {
    title: string;
    source: string;
    url?: string;
    finding: string;
    authority: string;
  }[];
  suspicious_evidence: {
    title: string;
    source: string;
    finding: string;
  }[];
  unresolved_ambiguities: string[];
  recommendation: string;
}

// ==============================================================================
// LEGITIFY DOMAIN & TYPE DEFINITIONS
// Evidence-First Trust Intelligence Matrix
// ==============================================================================

export type ScanEntityType =
  | "company"
  | "recruiter"
  | "domain"
  | "certificate"
  | "offer"
  | "document"
  | "job_offer"
  | "website";

export type ScanStatus =
  | "QUEUED"
  | "EXTRACTING"
  | "VALIDATING"
  | "NORMALIZING"
  | "LOOKING_UP"
  | "VERIFYING"
  | "SCORING"
  | "ML_ANALYSIS"
  | "AI_SYNTHESIS"
  | "GENERATING_REPORT"
  | "COMPLETED"
  | "FAILED";

export type RiskLevel =
  | "CRITICAL"
  | "HIGH"
  | "MODERATE"
  | "LOW"
  | "VERY LOW"
  | "UNKNOWN";

export type Verdict =
  | "LIKELY LEGITIMATE"
  | "LOW RISK"
  | "MODERATE RISK"
  | "HIGH RISK"
  | "LIKELY SCAM"
  | "INSUFFICIENT_EVIDENCE"
  | "INSUFFICIENT EVIDENCE"
  | "NEUTRAL / REVIEW REQUIRED";

export type CertificateStatus =
  | "VERIFIED_AUTHENTIC"
  | "LIKELY_AUTHENTIC"
  | "UNVERIFIED"
  | "SUSPICIOUS"
  | "LIKELY_FRAUDULENT";

export type EvidenceTypeCategory =
  | "VERIFIED_FACT"
  | "STRONG_INDICATOR"
  | "WEAK_INDICATOR"
  | "COMMUNITY_SIGNAL"
  | "UNVERIFIED"
  | "CONTRADICTORY_EVIDENCE"
  | "MISSING_EVIDENCE";

export type EvidenceCategory =
  | "COMPANY"
  | "REGISTRY"
  | "DOMAIN"
  | "EMAIL"
  | "RECRUITER"
  | "CERTIFICATE"
  | "OFFER"
  | "DOCUMENT"
  | "THREAT"
  | "PUBLIC_REPORT"
  | "CONSISTENCY"
  | "RULE_ENGINE"
  | "ML_MODEL"
  | "AI_ANALYSIS";

export type EvidenceStatus = "VERIFIED" | "WARNING" | "NEGATIVE" | "UNKNOWN";
export type EvidenceSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type EvidenceStrength = "VERY_STRONG" | "STRONG" | "MEDIUM" | "WEAK" | "UNVERIFIED";

export interface EvidenceItem {
  id?: string;
  scan_id?: string;
  category: EvidenceCategory;
  evidence_type_category?: EvidenceTypeCategory;
  evidence_type?: string;
  source_name: string;
  source_url?: string;
  title: string;
  snippet?: string;
  evidence_text?: string;
  claim?: string;
  evidence_strength: EvidenceStrength;
  status: EvidenceStatus;
  severity: EvidenceSeverity;
  verified: boolean;
  confidence: number; // 0 - 100
  raw_reference?: string;
  supporting_data?: Record<string, any>;
  collected_at?: string;
}

export interface RuleEvaluation {
  rule_id: string;
  name: string;
  description: string;
  triggered: boolean;
  severity: EvidenceSeverity;
  score_impact: number;
  explanation: string;
  evidence_required: string[];
}

export interface MLPredictionResult {
  model_name: string;
  model_version: string;
  feature_version: string;
  predicted_class: "LEGITIMATE" | "SUSPICIOUS" | "SCAM";
  scam_probability: number; // 0.0 - 1.0
  fraud_probability?: number; // 0.0 - 1.0
  confidence: number; // 0 - 100
  feature_importances: { feature: string; weight: number; contribution: string }[];
  evaluated_at: string;
}

export interface EvidenceCompleteness {
  overall_percentage: number; // 0 - 100
  breakdown: {
    company: { observed: number; expected: number; percentage: number };
    domain: { observed: number; expected: number; percentage: number };
    recruiter: { observed: number; expected: number; percentage: number };
    certificate: { observed: number; expected: number; percentage: number };
    document: { observed: number; expected: number; percentage: number };
    threat: { observed: number; expected: number; percentage: number };
  };
  missing_evidence: string[];
  score?: number;
  percentage?: number;
  category?: string;
  summary?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: "company" | "legal_entity" | "domain" | "recruiter" | "offer" | "certificate" | "issuer" | "threat" | "document";
  status: "verified" | "neutral" | "suspicious" | "threat" | "unverified";
  details?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  label: string;
  type: "OWNS" | "USES" | "SENDS" | "AUTHORED" | "REFERENCES" | "ISSUED_BY" | "FLAGGED_BY" | "SPOOFED_BY";
  status: "verified" | "neutral" | "suspicious" | "threat";
}

export interface EntityGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CertificateVerificationData {
  certificate_id?: string;
  recipient_name?: string;
  course_or_program?: string;
  issuer_name?: string;
  issuer_domain?: string;
  issue_date?: string;
  expiry_date?: string;
  verification_url?: string;
  qr_code_detected: boolean;
  qr_code_payload?: string;
  qr_domain_match: boolean;
  status: CertificateStatus;
  verification_level: number; // 1 - 10
  authenticity_confidence: number; // 0 - 100
  issuer_verified: boolean;
  id_verified: boolean;
  summary: string;
  evidence: EvidenceItem[];
}

export interface ScoreTraceConstraint {
  constraint: string;
  ceiling: number;
  reason: string;
  applied: boolean;
}

export interface ScoreTraceDimension {
  dimension: string;
  name: string;
  weight: number;
  normalized_weight: number;
  active: boolean;
  status: 'VERIFIED' | 'UNVERIFIED' | 'SUSPICIOUS' | 'CONTRADICTED' | 'FLAGGED';
  score: number;
  weighted_contribution: number;
  evidence_ids: string[];
  reason: string;
}

export interface ScoreTrace {
  pre_constraint_score: number;
  active_weight_sum: number;
  dimensions: ScoreTraceDimension[];
  rule_impact: number;
  constraints_triggered: ScoreTraceConstraint[];
  final_score: number;
  verdict: string;
  formula: string;
}

export interface ScoreComponent {
  name: string;
  weight: number;
  score: number; // 0 - 100
  weighted_score: number; // score * weight
  confidence: number; // 0 - 100
  reason: string;
  evidence_count: number;
  active?: boolean;
  status?: 'VERIFIED' | 'UNVERIFIED' | 'SUSPICIOUS' | 'CONTRADICTED' | 'FLAGGED';
  evidence_ids?: string[];
}

export interface DeterministicScoreResult {
  trust_score: number; // 0 - 100
  confidence_score: number; // 0 - 100
  risk_level: RiskLevel;
  verdict: Verdict;
  components: Record<string, ScoreComponent>;
  positive_signals: string[];
  warning_signals: string[];
  critical_signals: string[];
  rules_triggered: RuleEvaluation[];
  hard_caps_applied?: string[];
  scoring_model_version?: string;
  score_trace?: ScoreTrace;
}

export interface ScanRecord {
  id: string;
  user_id: string;
  entity_type: ScanEntityType;
  entity_value: string;
  normalized_entity_name?: string;
  email?: string;
  domain?: string;
  website?: string;
  status: ScanStatus;
  trust_score?: number;
  confidence_score?: number;
  risk_level?: RiskLevel;
  verdict?: Verdict;
  metadata?: Record<string, any>;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface LegitifyReport {
  scan_id: string;
  entity_name: string;
  entity_type: ScanEntityType;
  trust_score: number;
  confidence: number;
  evidence_completeness: EvidenceCompleteness;
  risk_level: RiskLevel;
  verdict: Verdict;
  executive_summary: string;
  structured_explanation: {
    what_we_found: string[];
    why_it_matters: string[];
    what_supports_it: string[];
    what_contradicts_it: string[];
    what_is_unknown: string[];
    recommendation: string;
  };
  recommendation: string;
  positive_signals: string[];
  warning_signals: string[];
  critical_signals: string[];
  missing_evidence: string[];
  company_verification: {
    legal_name?: string;
    normalized_name?: string;
    status?: string;
    registry_status: string;
    registration_number?: string;
    registered_address?: string;
    country?: string;
    state?: string;
    city?: string;
    website?: string;
    domain?: string;
    last_verified?: string;
    source?: string;
  };
  domain_analysis: {
    domain?: string;
    registrar?: string;
    age_days?: number;
    registration_date?: string;
    expiration_date?: string;
    ssl_valid?: boolean;
    ssl_issuer?: string;
    reputation_score?: number;
    threat_status?: string;
    lookalike_detected?: boolean;
    lookalike_target?: string;
  };
  recruiter_analysis: {
    email?: string;
    display_name?: string;
    domain?: string;
    domain_alignment?: string;
    free_email_provider?: boolean;
    spf_status?: string;
    dkim_status?: string;
    dmarc_status?: string;
    known_threat?: boolean;
  };
  certificate_verification?: CertificateVerificationData;
  document_analysis?: {
    visual_forensics?: VisualForensicsData;
    filename?: string;
    mime_type?: string;
    detected_company_name?: string;
    detected_signatory?: string;
    detected_domain?: string;
    detected_email?: string;
    extracted_entities?: Record<string, any>;
    requested_fees?: {
      amount?: string;
      reason?: string;
      channel?: string;
    }[];
    fee_details?: {
      category: string;
      amount?: string;
      recipient?: string;
      channel?: string;
      is_refundable?: boolean;
      refund_terms?: string;
      deadline?: string;
      exact_quote: string;
      why_it_matters: string;
      confidence: number;
    }[];
    candidate_compensation?: {
      type: 'STIPEND' | 'SALARY' | 'CTC' | 'REIMBURSEMENT';
      amount?: string;
      raw_quote?: string;
    };
  };
  threat_intelligence: {
    matched_iocs_count: number;
    indicators: {
      type: string;
      value: string;
      threat_type: string;
      severity: string;
      source: string;
    }[];
  };
  ml_evaluation?: MLPredictionResult;
  rules_evaluated: RuleEvaluation[];
  public_community_evidence: {
    source: string;
    title: string;
    snippet: string;
    url?: string;
    sentiment: string;
  }[];
  web_intelligence?: {
    searches_conducted: string[];
    official_sources_matched: { title: string; url: string; reliability: number; domain: string }[];
    reputable_reviews_found: { platform: string; sentiment: string; summary: string }[];
    community_complaint_clusters: { pattern: string; count: number; confidence: number; samples: string[] }[];
    total_sources_evaluated: number;
  };
  contradictions_detected?: {
    type: string;
    field: string;
    claimed_value: string;
    verified_value: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
    detail: string;
  }[];
  consistency_analysis: {
    item: string;
    status: "MATCH" | "MISMATCH" | "WARNING" | "UNKNOWN";
    detail: string;
  }[];
  entity_graph: EntityGraphData;
  timeline: {
    time: string;
    event: string;
    detail: string;
    status: "ok" | "warn" | "error";
  }[];
  evidence_sources: {
    provider: string;
    url?: string;
    status: "AVAILABLE" | "UNAVAILABLE" | "CACHED";
    latency?: string;
  }[];
  limitations: string[];
  disclaimer: string;
  company_name?: string;
  confidence_score?: number;
  input_type?: string;
  processing_time_ms?: number;
  dimension_scores?: {
    rules: number;
    nlp: number;
    ner: number;
    document_authenticity?: number;
    company_legal?: number;
    domain_security?: number;
    recruiter_auth?: number;
    financial_safety?: number;
    certificate_auth?: number;
    ml_fraud_model?: number;
    threat_intel?: number;
    community_evidence?: number;
    consistency_cross_check?: number;
  };
  components?: Record<string, ScoreComponent>;
  triggered_flags?: {
    rule: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    message: string;
    score: number;
  }[];
  next_steps?: string[];
  entity_value?: string;
  evidence?: EvidenceItem[];
  ai_synthesis?: any;
  company_record?: any;
  has_fee_demand?: boolean;
  score_trace?: ScoreTrace;
  extracted_offer_parts?: ExtractedOfferParts;
  gemini_cross_examination?: GeminiCrossExaminationReport;
  gemini_reconciliation?: GeminiReconciliationReport;
  dual_rag_citations?: DualRAGCitations;
  signatory_forensics?: {
    signature_detected: boolean;
    signature_type: VisualSignatureType;
    signatory_name?: string;
    signatory_title?: string;
    signatory_department?: string;
    identity_state: SignatoryVerificationState;
    page?: number;
    evidence_ids: string[];
    detection_method?: string;
  };
  pipeline_trace?: PipelineTrace;
  rules_triggered?: RuleEvaluation[];
  red_flags?: any[];
  hard_caps_applied?: string[];
  extracted_claims?: any[];
  assessments?: AssessmentItem[];
  overall_risk_score?: number;
  external_research?: any;
}

export type AssessmentRiskBand = 'LOW_RISK' | 'MINOR_IRREGULARITIES' | 'MODERATE_RISK' | 'HIGH_RISK' | 'CRITICAL_RISK' | 'INSUFFICIENT_EVIDENCE';

export interface AssessmentItem {
  id: string;
  name: string;
  risk_score: number; // 0 - 100 (higher = greater concern)
  risk_band: AssessmentRiskBand;
  risk_band_label: string;
  evidence_found: string;
  why_it_matters: string;
  evidence_strength: 'High' | 'Moderate' | 'Contextual' | 'STRONG' | 'WEAK' | 'INSUFFICIENT' | 'CONTRADICTORY';
  recommended_next_step: string;
  insufficient_evidence?: boolean;
  exact_quote?: string;
  amount?: string;
  recipient?: string;
  confidence_level?: number;
  limitations?: string;
}

export interface ExtractedOfferParts {
  roles: string[];
  stipends: Array<{
    rawText: string;
    amount?: string;
    currency?: string;
    period?: 'month' | 'week' | 'year' | 'lump-sum' | 'unknown';
    plausibility: 'PLAUSIBLE' | 'UNUSUAL' | 'UNVERIFIED' | 'CONTRADICTORY';
    reason?: string;
  }>;
  joiningDates: Array<{
    rawText: string;
    parsedDate?: string;
    urgencyClassification: 'NORMAL' | 'URGENT_24H' | 'URGENT_48H' | 'RETROACTIVE' | 'UNVERIFIED';
  }>;
  signatories: Array<{
    name: string;
    title?: string;
    department?: string;
    isVerifiedCorporateSignatory?: boolean;
    status: 'VERIFIED' | 'UNVERIFIED' | 'NOT_FOUND' | 'SUSPICIOUS' | 'OBSERVED' | 'CORROBORATED' | 'CONTRADICTED';
  }>;
  selectionStatements: string[];
  logoReferences: string[];
}

export interface GeminiCrossExaminationReport {
  engine: 'GEMINI';
  model: string;
  status: string;
  verdict?: string;
  confidence?: string;
  summary: string;
  riskSignals: Array<{ finding: string; confidence?: string; evidenceId: string }>;
  positiveSignals: Array<{ finding: string; confidence?: string; evidenceId: string }>;
  sources: Array<{ sourceId: string; title: string; publisher: string; url?: string; authorityTier: number; finding: string }>;
  unverifiedItems: string[];
  contradictions: string[];
  recommendedActions: string[];
  searchCoverage: {
    searchPerformed: boolean;
    queriesAttempted: string[];
    sourcesExamined: number;
    authoritativeSourcesFound: number;
  };
}

export interface GeminiReconciliationReport {
  agreements: string[];
  contradictions: string[];
  unknowns: string[];
  finalAssessment: string;
  pathA_trust_score: number;
  pathA_verdict: string;
  gemini_verdict: string;
  reconciliation_notes: string;
}

export interface DualRAGCitations {
  document_citations: Array<{ citation: string; content: string; page?: number; relevance: number }>;
  external_citations: Array<{ citation: string; source: string; content: string; relevance: number }>;
  formatted_context: string;
}

export interface ProviderResult<T = any> {
  provider: string;
  success: boolean;
  available: boolean;
  data?: T;
  evidence: EvidenceItem[];
  source_url?: string;
  retrieved_at: string;
  latency_ms?: number;
  error_code?: string;
  error_message?: string;
}

export interface PipelineTraceEntry {
  stage: string;
  status: 'PASS' | 'FAIL' | 'SKIP' | 'UNAVAILABLE';
  durationMs: number;
  detail: string;
  evidenceIds?: string[];
  counts?: Record<string, number>;
}

export interface PipelineTrace {
  scanId: string;
  startedAt: string;
  completedAt?: string;
  stages: PipelineTraceEntry[];
  totalDurationMs?: number;
}

