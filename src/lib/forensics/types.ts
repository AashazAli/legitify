// ==============================================================================
// LEGITIFY FORENSIC SUITE - DATA TYPES & INTERFACES
// Deterministic Browser-Side Cybersecurity Forensics
// ==============================================================================

export type SupportedMimeType = 'image/png' | 'image/jpeg' | 'image/webp' | 'image/tiff' | 'application/pdf';

export interface MagicValidationResult {
  isValid: boolean;
  detectedFormat: string | null;
  expectedHex: string;
  actualHex: string;
  mimeType: string;
  errorMessage?: string;
}

export interface ChainOfCustody {
  sha256Hash: string;
  fileName: string;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  magicSignatureHex: string;
  detectedMimeType: string;
  declaredMimeType: string;
  ingestionTimestamp: string;
  clientEnvironment: string;
  custodyId: string;
}

export interface MetadataTagEntry {
  tag: string;
  group: string;
  rawValue: string;
  sanitizedValue: string;
  status: 'VERIFIED' | 'NEUTRAL' | 'ALTERED' | 'SUSPICIOUS';
  implication: string;
  riskPenalty: number;
}

export interface ExtractedMetadata {
  softwareDetected?: string;
  modifyingSoftwareFlagged: boolean;
  modifyingSoftwareList: string[];
  createDate?: string;
  modifyDate?: string;
  cameraMake?: string;
  cameraModel?: string;
  hasExifData: boolean;
  tagsCount: number;
  tags: MetadataTagEntry[];
  timestampDivergenceHours?: number;
  metadataScore: number; // 0 - 100
  metadataFindings: string[];
}

export interface LuminanceBin {
  binRange: string;
  count: number;
  percentage: number;
}

export interface PixelForensicResult {
  width: number;
  height: number;
  totalPixels: number;
  meanLuminance: number;
  stdDevLuminance: number;
  luminanceVariance: number;
  laplacianEdgeVariance: number; // High-frequency sharpness vs synthetic blur
  blockVarianceDisparity: number; // 8x8 DCT grid artifact variance / splicing indicator
  compressionArtifactIndex: number; // 0 - 100 compression consistency
  clippingRatio: number; // Fraction of under/over exposed pixels
  histogram: LuminanceBin[];
  pixelScore: number; // 0 - 100
  pixelFindings: string[];
}

export interface OCRWordConfidence {
  text: string;
  sanitizedText: string;
  confidence: number; // 0 - 100
  bbox?: {
    x0: number;
    y0: number;
    x1: number;
    y1: number;
  };
  isSuspiciousKeyword?: boolean;
}

export interface OCRForensicResult {
  rawText: string;
  sanitizedText: string;
  averageConfidence: number; // 0 - 100
  minConfidence: number;
  maxConfidence: number;
  wordCount: number;
  lowConfidenceWordCount: number; // Confidence < 60%
  suspiciousKeywordsFound: string[];
  words: OCRWordConfidence[];
  confidenceBuckets: { range: string; count: number }[];
  ocrScore: number; // 0 - 100
  ocrFindings: string[];
}

export interface DetectedRiskEntry {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  mitigation: string;
}

export interface EvidenceLockerEntry {
  id: string;
  category: string;
  source: string;
  claim: string;
  status: 'VERIFIED' | 'WARNING' | 'CRITICAL';
  confidence: number;
  tier: string;
}

export interface DocumentStructureItem {
  id: string;
  name: string;
  passed: boolean;
  details: string;
  weight: number;
}

export interface DocumentStructureResult {
  structureScore: number; // 0 - 100
  status: 'STANDARD_COMPLIANT' | 'STRUCTURAL_ANOMALIES' | 'NON_STANDARD_FORMAT';
  hasCorporateHeader: boolean;
  hasRegisteredAddress: boolean;
  hasOfficialReferenceNumber: boolean;
  referenceNumber?: string;
  hasFormalDate: boolean;
  documentDate?: string;
  hasPersonalizedAddressee: boolean;
  candidateName?: string;
  hasSpecificRole: boolean;
  jobRole?: string;
  hasClearDurationOrStartDate: boolean;
  durationOrDate?: string;
  hasStipendOrCompensationTerms: boolean;
  hasConfidentialityOrIP: boolean;
  hasAuthorizedSignatoryBlock: boolean;
  signatoryTitle?: string;
  signatoryName?: string;
  signatureType?: string;
  signatureDetected?: boolean;
  identityState?: string;
  hasAcceptanceProcedure: boolean;
  passedChecksCount: number;
  totalChecksCount: number;
  structureChecks: DocumentStructureItem[];
  missingElements: string[];
}

export interface DimensionBreakdownItem {
  id: string;
  name: string;
  score: number;
  weight: number;
  status: 'VERIFIED' | 'WARNING' | 'CRITICAL';
  summary: string;
}

export interface DocumentSemanticsResult {
  detectedCompany?: string;
  detectedEmails: string[];
  recruiterEmail?: string;
  isFreeWebmail: boolean;
  freeWebmailDomains: string[];
  detectedRole?: string;
  detectedStipend?: string;
  hasFeeDemand: boolean;
  feeDemandKeywords: string[];
  hasInformalChannels: boolean;
  informalChannels: string[];
  hasGenericGreeting: boolean;
  hasUrgency: boolean;
  hasDirectSelectionNoInterview: boolean;
  hasCinNumber: boolean;
  detectedCin?: string;
  hasLegalTerms: boolean;
  contentIntegrityScore: number; // 0 - 100
  structure?: DocumentStructureResult;
  findings: string[];
  riskFlags: DetectedRiskEntry[];
  evidenceItems: EvidenceLockerEntry[];
}

export interface ForensicScoreResult {
  metadataScore: number;       // Weight
  pixelScore: number;          // Weight
  ocrScore: number;            // Weight
  contentScore?: number;       // Weight (Document Semantics, Email & Offer Legality)
  structureScore?: number;     // Weight (Standard Corporate Structure & Format Compliance)
  authenticityScore: number;   // 0 - 100 (Higher = more authentic)
  manipulationProbability: number; // 100 - authenticityScore
  verdict: 'AUTHENTIC_VERIFIED' | 'ANOMALOUS_SUSPICIOUS' | 'FORGED_CRITICAL';
  verdictLabel: string;
  verdictSeverity: 'low' | 'moderate' | 'critical';
  confidenceMetric: number;    // Mathematical confidence in the forensic assessment
  executiveSummary: string;
  reasons: {
    whatWeFound: string[];
    whyItMatters: string[];
    verifiedSignals: string[];
    riskIndicators: string[];
    recommendedActions: string[];
  };
  dimensionBreakdown?: DimensionBreakdownItem[];
  detectedRisks?: DetectedRiskEntry[];
  evidenceLocker?: EvidenceLockerEntry[];
  structureAnalysis?: DocumentStructureResult;
  docAuthScore?: number;
  hardCapsApplied?: Array<{ limit: number; reason: string }>;
  riskScore?: number;          // 0 - 100 (Higher = greater risk/concern)
  assessments?: any[];         // Structured assessments with 0-100 risk score each
}

export interface CompleteForensicReport {
  custody: ChainOfCustody;
  validation: MagicValidationResult;
  metadata: ExtractedMetadata;
  pixel: PixelForensicResult;
  ocr: OCRForensicResult;
  semantics?: DocumentSemanticsResult;
  scoring: ForensicScoreResult;
  sanitizedPreviewUrl: string;
  analysisDurationMs: number;
}

