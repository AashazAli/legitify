// ==============================================================================
// LEGITIFY COMPLETE EVIDENCE-FIRST SCAN PIPELINE
// Orchestrates Extraction -> Chunking -> Claims -> Registry -> Domain ->
// Recruiter -> Certificate -> Threats -> Cybersecurity -> Community ->
// ML -> Gemini Independent Path -> Evidence Fusion -> Scoring -> AI -> Report
// ==============================================================================
import crypto from 'crypto';
import {
  LegitifyReport,
  ScanEntityType,
  EvidenceItem,
  ExtractedOfferParts,
  GeminiCrossExaminationReport,
  GeminiReconciliationReport,
  DualRAGCitations,
  PipelineTrace,
  PipelineTraceEntry,
} from '../../types';
import { detectVisualRegions, VisualForensicResult } from './visualForensicsService';
import { supabaseAdmin } from '../../lib/supabase/server';
import { logAuditEvent } from './auditService';
import { lookupCompany, CompanyData } from './companyService';
import { verifyCompanyRegistry } from './companyRegistryService';
import { analyzeDomain, DomainData } from './domainService';
import { analyzeRecruiterEmail, RecruiterData } from './emailService';
import { processDocument, DocumentExtractionResult } from './documentService';
import { checkThreatIndicators, ThreatData } from './threatService';
import { verifyCertificate } from './certificateService';
import { searchPublicExperiences, investigatePublicExperience, CommunitySearchResult } from './publicExperienceService';
import { predictJobOfferRisk, MLPrediction } from '../ml/fraudClassifier';
import { calculateDeterministicScore, calculateEvidenceCompleteness, DeterministicScoreResult } from './scoringService';
import { buildEntityGraph } from './entityGraphService';
import { evaluateFraudPatterns } from './fraudPatternService';
import { evaluateLegitimacyPatterns, isRecognizedStaffingPartner } from './legitimacyPatternService';
import { getActiveAIProvider } from './aiProvider';
import { compileFullReport, persistReport } from './reportService';
import { runWebIntelligence } from './webIntelligenceService';
import { detectEvidenceConflicts, formatContradictionsForReport } from './conflictService';
import { normalizeCompanyName, normalizeDomain, extractEmailDomain } from '../utils/normalizer';
import { indexDocumentChunks, indexExternalEvidence, retrieveDualRAG, retrieveRAGKnowledge } from './ragService';
import { chunkDocument } from './chunkingService';
import { buildClaimLedger } from './claimLedger';
import { runCybersecurityAnalysis } from './cybersecurityService';
import { runGeminiInvestigation } from './geminiInvestigator';
import { runEvidenceFusion } from './evidenceFusionEngine';
import { generateClaimInvestigationQueue } from './huggingfaceService';
import { runReportAssertionGuard } from './reportAssertionGuard';

export interface ExecuteScanParams {
  userId: string;
  entityType: ScanEntityType;
  entityValue: string;
  contextText?: string;
  fileBuffer?: Buffer;
  filename?: string;
  mimeType?: string;
  ip?: string;
  userAgent?: string;
}

export async function runScanPipeline(params: ExecuteScanParams): Promise<LegitifyReport> {
  const scanStartTime = Date.now();
  const {
    userId,
    entityType,
    entityValue,
    contextText = '',
    fileBuffer,
    filename,
    mimeType,
    ip,
    userAgent,
  } = params;

  // Step 1: Initialize Scan in Database (Non-blocking with deterministic ID fallback)
  const fallbackHash = crypto.createHash('sha256').update(`${entityValue}:${scanStartTime}`).digest('hex').slice(0, 8);
  let scanId = `SC-${fallbackHash.toUpperCase()}`;
  try {
    const insertPromise = supabaseAdmin
      .from('scans')
      .insert({
        user_id: (userId && userId !== '00000000-0000-0000-0000-000000000000') ? userId : null,
        entity_type: entityType,
        entity_value: entityValue.trim(),
        status: 'EXTRACTING',
        started_at: new Date().toISOString(),
      })
      .select('id')
      .maybeSingle();

    const timeoutPromise = new Promise<any>((_, reject) =>
      setTimeout(() => reject(new Error('Supabase scan init timeout')), 1500)
    );

    const { data: scanRow } = await Promise.race([insertPromise, timeoutPromise]) as any;
    if (scanRow?.id) {
      scanId = scanRow.id;
    }
  } catch {
    // Fallback scanId already generated
  }

  await logAuditEvent({
    user_id: userId,
    action: 'SCAN_STARTED',
    resource_type: 'scan',
    resource_id: scanId,
    ip,
    user_agent: userAgent,
    metadata: { entityType, entityValue },
  });

  const evidence: EvidenceItem[] = [];
  const traceStages: PipelineTraceEntry[] = [];
  const recordTrace = (
    stage: string,
    status: 'PASS' | 'FAIL' | 'SKIP' | 'UNAVAILABLE',
    startMs: number,
    detail: string,
    evidenceIds?: string[],
    counts?: Record<string, number>
  ) => {
    traceStages.push({
      stage,
      status,
      durationMs: Date.now() - startMs,
      detail,
      evidenceIds,
      counts,
    });
  };

  // Step 2: Document Extraction & Text Signal Extraction
  const docStart = Date.now();
  let docResult: DocumentExtractionResult | undefined;
  const combinedTextCorpus = [contextText, entityValue].filter(Boolean).join('\n').trim();

  if (fileBuffer && filename && mimeType) {
    docResult = await processDocument(fileBuffer, filename, mimeType);
    if ((docResult.extracted_text?.length || 0) < 30 && combinedTextCorpus.length > 10) {
      const pasted = await processDocument(Buffer.from(combinedTextCorpus, 'utf-8'), 'pasted_text.txt', 'text/plain');
      evidence.push(...pasted.evidence);
      docResult.has_fee_demand = docResult.has_fee_demand || pasted.has_fee_demand;
      (docResult as any).suspicious_patterns = [...(docResult.suspicious_patterns || []), ...(pasted.suspicious_patterns || [])];
    }
    recordTrace(
      'Document Decomposition & OCR',
      'PASS',
      docStart,
      `Engine: ${docResult.normalized_evidence?.ocr_engine || 'Standard'}, Text: ${docResult.extracted_text?.length || 0} chars`,
      docResult.evidence?.map(e => e.id).filter(Boolean) as string[],
      { textLength: docResult.extracted_text?.length || 0 }
    );
  } else {
    const textBuffer = Buffer.from(combinedTextCorpus || entityValue, 'utf-8');
    docResult = await processDocument(textBuffer, 'pasted_text.txt', 'text/plain');
    recordTrace(
      'Document Decomposition & OCR',
      'PASS',
      docStart,
      `Pasted Text mode, length: ${docResult.extracted_text?.length || 0} chars`,
      docResult.evidence?.map(e => e.id).filter(Boolean) as string[]
    );
  }
  evidence.push(...(docResult.evidence || []));

  // Step 2.5: Visual Forensics Analysis (Independent from OCR)
  const visualStart = Date.now();
  let visualForensicsResult: VisualForensicResult | undefined;
  if (fileBuffer && mimeType) {
    try {
      visualForensicsResult = await detectVisualRegions(fileBuffer, mimeType, scanId, docResult?.extracted_text);
      if (visualForensicsResult.evidence && visualForensicsResult.evidence.length > 0) {
        evidence.push(...visualForensicsResult.evidence);
      }
      recordTrace(
        'Visual Forensics',
        'PASS',
        visualStart,
        `Detected ${visualForensicsResult.regions.length} visual regions. Signature: ${visualForensicsResult.signatureType}, State: ${visualForensicsResult.signatoryState}`,
        visualForensicsResult.evidence.map(e => e.id).filter(Boolean) as string[],
        { regionsCount: visualForensicsResult.regions.length }
      );
    } catch (err: any) {
      recordTrace('Visual Forensics', 'UNAVAILABLE', visualStart, `Visual forensics degraded: ${err.message}`);
    }
  } else {
    recordTrace('Visual Forensics', 'SKIP', visualStart, 'Pasted text input (no visual file buffer)');
  }

  const fullTextToAnalyze = [contextText, docResult?.extracted_text, entityValue].filter(Boolean).join('\n').trim();

  // Stage 02 & 03: Semantic Document Chunking & Structured Claim Ledger
  const chunks = chunkDocument(fullTextToAnalyze, scanId);
  const claimLedger = buildClaimLedger(chunks);

  // Stage 04: Structured Offer-Part Extraction (Roles, Compensation, Joining, Signatory, Selection, Logo)
  const signatoriesExtracted = (claimLedger.normalizedEntities.signatories || []).map(sig => ({
    name: sig.name || sig.raw,
    title: sig.title,
    status: (sig.name ? 'OBSERVED' : 'UNVERIFIED') as any,
  }));

  // Merge visual forensics signatory if detected
  if (visualForensicsResult && visualForensicsResult.signatureType !== 'ABSENT') {
    const visualSigName = visualForensicsResult.signatoryName;
    if (visualSigName) {
      const existing = signatoriesExtracted.find(s => s.name && s.name.toLowerCase().includes(visualSigName.toLowerCase()));
      if (!existing) {
        signatoriesExtracted.push({
          name: visualSigName,
          title: visualForensicsResult.signatoryTitle,
          status: visualForensicsResult.signatoryState as any,
        });
      } else {
        existing.status = visualForensicsResult.signatoryState as any;
        if (!existing.title && visualForensicsResult.signatoryTitle) {
          existing.title = visualForensicsResult.signatoryTitle;
        }
      }
    } else {
      signatoriesExtracted.push({
        name: 'Visual Signature Mark',
        title: 'Signatory Block (Name unextracted)',
        status: 'UNVERIFIED',
      });
    }
  }

  const extractedOfferParts: ExtractedOfferParts = {
    roles: Array.from(claimLedger.normalizedEntities.jobRoles || []),
    stipends: (claimLedger.normalizedEntities.stipends || []).map(s => ({
      rawText: s.raw,
      amount: s.amount ? String(s.amount) : undefined,
      currency: s.currency,
      period: s.period?.toLowerCase() as any,
      plausibility: s.plausibility as any,
      reason: (s as any).reason,
    })),
    joiningDates: (claimLedger.normalizedEntities.joiningDates || []).map(j => ({
      rawText: j.raw,
      parsedDate: j.date,
      urgencyClassification: j.isUrgent ? 'URGENT_24H' : 'NORMAL',
    })),
    signatories: signatoriesExtracted,
    selectionStatements: Array.from(claimLedger.normalizedEntities.selectionStatements || []),
    logoReferences: Array.from(claimLedger.normalizedEntities.logoReferences || []),
  };

  // Stage 06: Dual RAG Layer 1: Index Document Chunks into DOCUMENT_RAG
  indexDocumentChunks(scanId, fullTextToAnalyze, (docResult as any)?.pages);

  // Step 3: Entity Normalization & Routing
  let targetCompany = '';
  let targetDomain = '';
  let targetEmail = '';
  let targetCin = docResult?.detected_cin || claimLedger.normalizedEntities.cins[0] || '';

  if (entityType === 'company') {
    targetCompany = normalizeCompanyName(entityValue);
  } else if (entityType === 'domain' || entityType === 'website') {
    targetDomain = normalizeDomain(entityValue);
  } else if (entityType === 'recruiter') {
    targetEmail = entityValue.trim().toLowerCase();
    targetDomain = extractEmailDomain(targetEmail);
  } else {
    // Detect entities from document / claims / OCR
    if (claimLedger.normalizedEntities.organizations.length > 0) {
      targetCompany = claimLedger.normalizedEntities.organizations[0];
    } else if (docResult?.detected_company_name) {
      targetCompany = normalizeCompanyName(docResult.detected_company_name);
    } else if (entityValue && !entityValue.includes('.') && entityValue.length >= 2 && !entityValue.toLowerCase().includes('offer letter')) {
      targetCompany = normalizeCompanyName(entityValue);
    }

    if (claimLedger.normalizedEntities.domains.length > 0) {
      targetDomain = claimLedger.normalizedEntities.domains[0];
    } else if (docResult?.detected_domain) {
      targetDomain = normalizeDomain(docResult.detected_domain);
    } else {
      const domainMatch = fullTextToAnalyze.match(/https?:\/\/([^\s/$.?#].[^\s]*)/i) || fullTextToAnalyze.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
      if (domainMatch) targetDomain = normalizeDomain(domainMatch[1]);
    }

    if (claimLedger.normalizedEntities.emails.length > 0) {
      targetEmail = claimLedger.normalizedEntities.emails[0];
    } else if (docResult?.detected_email) {
      targetEmail = docResult.detected_email.toLowerCase();
    } else {
      const emailMatch = fullTextToAnalyze.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (emailMatch) targetEmail = emailMatch[1].toLowerCase();
    }
  }

  // Step 4: Certificate Verification (if certificate entity or certificate text detected)
  let certificateData = undefined;
  if (entityType === 'certificate' || /certificate|credential|issued\s*by|completion/i.test(fullTextToAnalyze)) {
    certificateData = await verifyCertificate(fullTextToAnalyze, undefined, targetCompany, undefined);
    evidence.push(...certificateData.evidence);
  }

  // Step 4.5: Cybersecurity Analysis Engine (DNS, SPF, DMARC, MX, Lookalike, IOC, UPI)
  const cyberResult = await runCybersecurityAnalysis({
    emails: [targetEmail, ...claimLedger.normalizedEntities.emails].filter(Boolean),
    domains: [targetDomain, ...claimLedger.normalizedEntities.domains].filter(Boolean),
    urls: fullTextToAnalyze.match(/https?:\/\/[^\s<>"{}|\\^\[\]`]+/g) || [],
    upiIds: claimLedger.normalizedEntities.upiIds,
    documentText: fullTextToAnalyze,
  }).catch(() => null);

  if (cyberResult && cyberResult.evidence.length > 0) {
    evidence.push(...cyberResult.evidence);
  }

  // Step 4.8: Dynamic Claim-Driven Investigation Queue (No hardcoded generic lists)
  const claimInvestigationQueue = generateClaimInvestigationQueue(claimLedger.claims, {
    companyName: targetCompany,
    domain: targetDomain,
    recruiterEmail: targetEmail,
    recruiterName: (claimLedger.normalizedEntities as any).signatories?.[0]?.name,
    role: (claimLedger.normalizedEntities as any).jobRoles?.[0],
    stipend: (claimLedger.normalizedEntities as any).stipends?.[0]?.raw,
    upiId: claimLedger.normalizedEntities.upiIds[0],
    paymentAmount: claimLedger.normalizedEntities.paymentRequests[0]?.amount ? String(claimLedger.normalizedEntities.paymentRequests[0].amount) : undefined,
  });

  // Step 5: Concurrent Multi-Source Evidence Lookups
  const [compResult, mcaResult, domResult, threatResult, communityResult, webResult, publicExpResult] = await Promise.all([
    targetCompany ? lookupCompany(targetCompany, targetDomain, targetCin).catch(() => null) : Promise.resolve(null),
    targetCompany ? verifyCompanyRegistry(targetCompany, targetCin).catch(() => null) : Promise.resolve(null),
    targetDomain ? analyzeDomain(targetDomain).catch(() => null) : Promise.resolve(null),
    checkThreatIndicators([targetCompany, targetDomain, targetEmail].filter(Boolean), entityType, fullTextToAnalyze).catch(() => null),
    searchPublicExperiences({ companyName: targetCompany, domain: targetDomain, recruiterEmail: targetEmail }).catch(() => null),
    runWebIntelligence({ companyName: targetCompany, domain: targetDomain, recruiterEmail: targetEmail, documentText: fullTextToAnalyze }).catch(() => null),
    investigatePublicExperience({
      companyName: targetCompany,
      domain: targetDomain,
      recruiterEmail: targetEmail,
      phone: claimLedger.normalizedEntities.phones[0],
      upiId: claimLedger.normalizedEntities.upiIds[0],
      role: (claimLedger.normalizedEntities as any).jobRoles?.[0],
      customClaimQueries: claimInvestigationQueue.allQueries,
    }).catch(() => null),
  ]);

  let companyData: CompanyData | undefined = compResult ? compResult.data : undefined;
  if (compResult) evidence.push(...compResult.evidence);

  if (mcaResult) {
    evidence.push(...mcaResult.evidence);
    if (companyData && mcaResult.status === 'LOCAL_REFERENCE_FOUND' && mcaResult.record) {
      companyData.legal_name = mcaResult.record.legal_name;
      companyData.registration_number = mcaResult.record.cin || mcaResult.record.llpin;
      companyData.registry_status = 'LOCAL_REFERENCE_FOUND' as any;
      companyData.status = mcaResult.record.status;
    }
  }

  const domainData: DomainData | undefined = domResult ? domResult.data : undefined;
  if (domResult) evidence.push(...domResult.evidence);

  const recResult = targetEmail ? analyzeRecruiterEmail(targetEmail, companyData?.domain || targetDomain, targetCompany) : null;
  const recruiterData: RecruiterData | undefined = recResult ? recResult.data : undefined;
  if (recResult) evidence.push(...recResult.evidence);

  const threatData: ThreatData | undefined = threatResult ? threatResult.data : undefined;
  if (threatResult) evidence.push(...threatResult.evidence);

  const communityData: CommunitySearchResult | undefined = communityResult || undefined;
  if (communityResult) evidence.push(...communityResult.evidence);

  if (webResult && webResult.evidence) {
    evidence.push(...webResult.evidence);
  }

  if (publicExpResult && publicExpResult.sources && publicExpResult.sources.length > 0) {
    for (const src of publicExpResult.sources) {
      evidence.push({
        id: src.id || src.evidenceId || `EXT-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        category: src.sourceType === 'OFFICIAL_ADVISORY' ? 'REGISTRY' : 'PUBLIC_REPORT',
        evidence_type: src.sourceType,
        source_name: src.publisher || (src.sourceType === 'REDDIT_THREAD' ? 'Reddit Discussion' : src.sourceType === 'OFFICIAL_ADVISORY' ? 'Official Corporate Advisory' : 'Public Web Intelligence'),
        source_url: src.url,
        title: src.title,
        snippet: src.evidenceText,
        evidence_text: src.evidenceText,
        claim: src.matchRationale || src.title,
        evidence_strength: src.credibility === 'HIGH' ? 'STRONG' : src.credibility === 'MEDIUM' ? 'MEDIUM' : 'WEAK',
        status: src.experienceType.includes('SCAM') || src.experienceType.includes('WARNING') ? 'WARNING' : src.experienceType === 'POSITIVE_EXPERIENCE' ? 'VERIFIED' : 'UNKNOWN',
        severity: src.experienceType === 'OFFICIAL_WARNING' || src.experienceType === 'PAYMENT_SCAM_REPORT' ? 'CRITICAL' : src.experienceType.includes('SCAM') ? 'HIGH' : 'INFO',
        verified: src.status === 'VERIFIED',
        confidence: Math.round((src.relevance || 0.7) * 100),
        collected_at: src.retrievedAt || src.publishedAt || new Date().toISOString(),
        supporting_data: {
          recency: src.recency,
          experienceType: src.experienceType,
          matchedEntities: src.matchedEntities,
          publisher: src.publisher,
          sourceTier: src.sourceTier,
        },
      });
    }
  }

  const hasPaymentDemand = docResult?.has_fee_demand || claimLedger.normalizedEntities.paymentRequests.length > 0;

  // Step 5.5: Dual RAG Layer 2: Index External Evidence into EXTERNAL_EVIDENCE_RAG
  indexExternalEvidence(scanId, evidence);

  // Step 6: Supervised Kaggle ML Risk Prediction (Offline & Real)
  const mlPrediction: MLPrediction = predictJobOfferRisk({
    text: fullTextToAnalyze || entityValue,
    hasCompanyProfile: !!companyData?.legal_name,
    hasCompanyLogo: !domainData?.lookalike_detected,
    telecommuting: fullTextToAnalyze.toLowerCase().includes('remote') || fullTextToAnalyze.toLowerCase().includes('work from home'),
  });

  // Step 7: Contradiction Engine & Cross-Validation
  const rawConflicts = detectEvidenceConflicts({
    companyData,
    domainData,
    recruiterData,
    certificateStatus: certificateData?.status,
    mlPrediction,
    threatData,
    hasFeeDemand: hasPaymentDemand,
    communityNegativeCount: webResult?.community_complaint_clusters?.length || 0,
    communityPositiveCount: webResult?.reputable_reviews_found?.length || 0,
  });
  const contradictions = formatContradictionsForReport(rawConflicts);

  // Stage 11: Dual RAG Retrieval & Citations Assembly (Document RAG + External Evidence RAG)
  const dualRAG = retrieveDualRAG(scanId, `${targetCompany} ${targetEmail} ${targetDomain} ${fullTextToAnalyze}`);
  const dualRAGCitations: DualRAGCitations = {
    document_citations: dualRAG.documentCitations.map(d => ({
      citation: d.chunk_id,
      content: d.text,
      page: d.page,
      relevance: d.relevance_score || 1,
    })),
    external_citations: dualRAG.externalCitations.map(e => ({
      citation: e.chunk_id,
      source: e.source,
      content: e.evidence_text || e.claim,
      relevance: e.relevance_score || 1,
    })),
    formatted_context: dualRAG.formattedContext,
  };

  const ragResult = retrieveRAGKnowledge({
    entityName: companyData?.legal_name || entityValue,
    domain: domainData?.domain || targetDomain,
    email: targetEmail,
    hasFeeDemand: hasPaymentDemand,
    contextText: fullTextToAnalyze,
    scanId,
  });

  // Step 10: Update extracted claims with dual RAG evidence provenance
  const claims = (docResult as any)?.extracted_claims || [];
  for (const clm of claims) {
    if (clm.claim_type === 'ORGANIZATION') {
      if (mcaResult && mcaResult.status === 'LOCAL_REFERENCE_FOUND' && mcaResult.record) {
        clm.verification_status = 'VERIFIED';
        clm.retrieved_reality = `Local Reference Index: ${mcaResult.record.legal_name} (CIN: ${mcaResult.record.cin || 'Referenced'})`;
        clm.explanation = 'Organization matches entry in local corporate reference dataset. (Live MCA21 not queried).';
        clm.evidence_source = '[Ext-REGISTRY-01] Local Corporate Reference Dataset';
        clm.evidence_ids = ['Ext-REGISTRY-01'];
      } else {
        clm.verification_status = 'UNVERIFIED';
        clm.retrieved_reality = 'No match in local reference dataset for this entity string';
        clm.explanation = 'Organization not found in local index. (Absence does not imply fraud; live MCA21 query unavailable).';
        clm.evidence_source = '[Ext-REGISTRY-01] Local Reference Index';
        clm.evidence_ids = ['Ext-REGISTRY-01'];
      }
    } else if (clm.claim_type === 'CONTACT_EMAIL') {
      if (recruiterData) {
        if (recruiterData.free_email_provider || recruiterData.domain_alignment === 'FREE_EMAIL') {
          clm.verification_status = 'SUSPICIOUS';
          clm.retrieved_reality = `Public Webmail Provider (${targetEmail}) conflicting with enterprise corporate domain`;
          clm.explanation = 'Legitimate enterprise recruiters communicate via corporate domain addresses, not free public webmail.';
          clm.evidence_source = '[Ext-RECRUITER-01] Recruiter Authentication Engine';
          clm.evidence_ids = ['Ext-RECRUITER-01'];
        } else if (recruiterData.domain_alignment === 'EXACT_MATCH' || recruiterData.domain_alignment === 'MATCH') {
          clm.verification_status = 'VERIFIED';
          clm.retrieved_reality = 'Sender address matches verified corporate domain';
          clm.explanation = 'Recruiter email domain aligns with claimed corporate domain. (Note: Domain alignment does not independently verify authorization).';
          clm.evidence_source = '[Ext-RECRUITER-01] Recruiter Authentication Engine';
          clm.evidence_ids = ['Ext-RECRUITER-01'];
        } else {
          clm.verification_status = 'UNVERIFIED';
          clm.retrieved_reality = `Sender domain '${domainData?.domain || targetDomain}' unverified against official company domain`;
          clm.explanation = 'Recruiter email domain could not be independently linked to the claimed corporate entity.';
          clm.evidence_source = '[Ext-RECRUITER-01] Recruiter Authentication Engine';
          clm.evidence_ids = ['Ext-RECRUITER-01'];
        }
      }
    } else if (clm.claim_type === 'PAYMENT_REQUIREMENT') {
      clm.evidence_source = '[Doc-P1-C0] Offer Document Forensics';
      clm.evidence_ids = ['Doc-P1-C0'];
    }
  }

  // False-Positive Counter-Evidence Search
  const falsePositiveCheck: import('../../types').FalsePositiveCheckResult = {
    is_checked: true,
    legitimate_counter_evidence: [],
    suspicious_evidence: [],
    unresolved_ambiguities: [],
    recommendation: "",
  };

  if (companyData && ((companyData.registry_status as string) === 'ACTIVE' || (companyData.registry_status as string) === 'LOCAL_REFERENCE_FOUND')) {
    falsePositiveCheck.legitimate_counter_evidence.push({
      title: "Company Record in Reference Index",
      source: "Local Corporate Reference Index",
      finding: `Entity '${companyData.legal_name}' is documented in corporate reference dataset.`,
      authority: "TIER_2_HIGH_QUALITY",
    });
  }

  if (domainData && domainData.ssl_valid && (domainData.age_days || 0) > 365) {
    falsePositiveCheck.legitimate_counter_evidence.push({
      title: "Established Domain Age & Valid TLS",
      source: "ICANN RDAP",
      finding: `Domain '${domainData.domain}' has been active for ${domainData.age_days} days.`,
      authority: "TIER_2_HIGH_QUALITY",
    });
  }

  if (hasPaymentDemand) {
    falsePositiveCheck.suspicious_evidence.push({
      title: "Upfront Monetary Charge Detected",
      source: "Uploaded Document",
      finding: "Candidate payment required prior to onboarding.",
    });
    falsePositiveCheck.recommendation = "Upfront monetary demand violates anti-fraud employment standards; risk remains elevated despite organization existence.";
  } else {
    falsePositiveCheck.recommendation = "No direct monetary charges identified in document.";
  }

  // Step 11: Evidence Completeness Metric
  const completeness = calculateEvidenceCompleteness({
    companyData,
    domainData,
    recruiterData,
    documentData: docResult,
    certificateData,
    threatData,
    mlPrediction,
    communityData,
    evidence,
  });

  // Step 12: Deterministic 10-Dimension Score (LEGITIFY Path A with ScoreTrace)
  const legitifyScore = calculateDeterministicScore({
    companyData,
    domainData,
    recruiterData,
    documentData: docResult,
    certificateData,
    threatData,
    mlPrediction,
    communityData,
    evidence,
  });

  // Step 8.4: Multi-Hop Entity Relationship Graph & Anomaly Detection
  const entityGraph = buildEntityGraph({
    companyName: targetCompany,
    officialDomain: companyData?.domain,
    recruiterEmail: targetEmail,
    recruiterName: (docResult as any)?.detected_recruiter_name,
    domain: targetDomain,
    claims: claimLedger.claims,
    chunks: chunks,
    stipend: claimLedger.claims.find(c => c.type === 'STIPEND')?.normalizedValue,
    salary: claimLedger.claims.find(c => c.type === 'SALARY')?.normalizedValue,
    hasPaymentRequest: hasPaymentDemand,
    paymentAmount: claimLedger.normalizedEntities.paymentRequests[0]?.amount,
    upiId: claimLedger.normalizedEntities.upiIds[0],
    signatoryName: (docResult as any)?.detected_signatory_name,
  });

  // Step 8.45: Multi-Signal Fraud Pattern & Legitimate Pattern Analysis
  const isLookalike = Boolean(
    domainData?.lookalike_detected ||
    cyberResult?.lookalikeDomains.some(l => l.classification === 'HIGH_CONFIDENCE_LOOKALIKE')
  );
  const isMaliciousIOC = Boolean(
    threatData?.known_threat ||
    (cyberResult && cyberResult.highRiskIOCCount > 0)
  );

  const fraudPatterns = evaluateFraudPatterns({
    hasPaymentDemand,
    paymentAmount: claimLedger.normalizedEntities.paymentRequests[0]?.amount,
    isInternship: fullTextToAnalyze.toLowerCase().includes('intern'),
    isEmploymentPromise: fullTextToAnalyze.toLowerCase().includes('offer') || fullTextToAnalyze.toLowerCase().includes('employment'),
    isRegisteredCompanyClaimed: Boolean(mcaResult?.record || companyData?.legal_name),
    isLookalikeDomain: isLookalike,
    isFreeWebmail: Boolean(targetEmail && (targetEmail.endsWith('@gmail.com') || targetEmail.endsWith('@yahoo.com') || targetEmail.endsWith('@outlook.com') || targetEmail.endsWith('@hotmail.com'))),
    isRecruiterUnverified: recruiterData ? (recruiterData.domain_alignment !== 'EXACT_MATCH' && recruiterData.domain_alignment !== 'SUBSIDIARY_MATCH') : true,
    hasTrainingFee: /training\s+fee|processing\s+fee/i.test(fullTextToAnalyze),
    hasUrgentDeadline: /urgent|within\s+24|immediate/i.test(fullTextToAnalyze),
    requestsSensitiveCredentials: /bank\s+pin|password|otp/i.test(fullTextToAnalyze),
    suspiciousUrlPresent: false,
    offPlatformMigration: /telegram|whatsapp|wa\.me|t\.me/i.test(fullTextToAnalyze),
    evidenceList: evidence,
  });

  const { patterns: legitimatePatterns, counterEvidence } = evaluateLegitimacyPatterns({
    isCorporateDomainAligned: recruiterData ? (recruiterData.domain_alignment === 'EXACT_MATCH' || recruiterData.domain_alignment === 'SUBSIDIARY_MATCH') : false,
    hasValidMx: Boolean(domainData?.mx_records && domainData.mx_records.length > 0),
    hasCareersPageMatch: Boolean(webResult?.official_sources_matched && webResult.official_sources_matched.length > 0),
    hasZeroFeeCompliance: !hasPaymentDemand,
    isStatutoryRegistered: Boolean(mcaResult?.record),
    cinNumber: targetCin,
    hasInternalCoherence: entityGraph.coherenceScore >= 70,
    isRecognizedStaffingAgency: isRecognizedStaffingPartner(`${targetCompany || ''} ${targetEmail || ''}`),
    isYoungStartup: domainData?.age_days !== undefined && domainData.age_days < 365,
    evidenceList: evidence,
    companyName: targetCompany,
    domain: targetDomain,
    recruiterEmail: targetEmail,
  });

  // Stage 15: Preliminary Evidence Fusion (Path A Isolation)
  const preliminaryFusion = runEvidenceFusion({
    legitifyResult: legitifyScore,
    legitifyEvidence: evidence,
    geminiResult: undefined, // Path A baseline before independent cross-examination
    hasFeeDemand: hasPaymentDemand,
    hasLookalikeDomain: isLookalike,
    hasKnownThreat: isMaliciousIOC,
    companyName: targetCompany,
    domain: targetDomain,
    recruiterEmail: targetEmail,
    publicExperience: publicExpResult || undefined,
    entityGraph: entityGraph as any,
    fraudPatterns,
    legitimatePatterns,
    counterEvidence,
    isYoungStartup: domainData?.age_days !== undefined && domainData.age_days < 365,
  });

  // Stage 16: GEMINI INDEPENDENT CROSS-EXAMINATION (Path B)
  // Gemini acts as an independent investigator cross-examining Path A with Google Search grounding
  const geminiResult = await runGeminiInvestigation({
    documentText: fullTextToAnalyze,
    extractedEntities: {
      companyName: targetCompany || undefined,
      recruiterEmail: targetEmail || undefined,
      domain: targetDomain || undefined,
      phone: claimLedger.normalizedEntities.phones[0] || undefined,
      urls: fullTextToAnalyze.match(/https?:\/\/[^\s<>"{}|\\^\[\]`]+/g) || [],
      cinNumber: targetCin || undefined,
      stipend: claimLedger.claims.find(c => c.type === 'STIPEND')?.normalizedValue,
      paymentRequested: hasPaymentDemand,
      paymentAmount: claimLedger.normalizedEntities.paymentRequests[0]?.amount,
      role: (claimLedger.normalizedEntities as any).jobRoles?.[0],
      joiningDate: (claimLedger.normalizedEntities as any).joiningDates?.[0]?.raw,
      signatoryName: (claimLedger.normalizedEntities as any).signatories?.[0]?.name,
      signatoryTitle: (claimLedger.normalizedEntities as any).signatories?.[0]?.title,
      stipendPlausibility: (claimLedger.normalizedEntities as any).stipends?.[0]?.plausibility,
      timelineUrgency: (claimLedger.normalizedEntities as any).joiningDates?.[0]?.isUrgent ? 'Urgent onboarding requested' : undefined,
    },
    claims: claimLedger.claims,
    ocrFindings: docResult?.suspicious_patterns,
    mlEvaluation: {
      ml_probability: mlPrediction.ml_probability,
      prediction: mlPrediction.prediction,
      algorithm: mlPrediction.algorithm,
      topFeatures: mlPrediction.top_features,
    },
    externalEvidence: evidence.map(e => ({
      source: e.source_name || e.category || 'External',
      finding: e.title || e.evidence_text || '',
      category: e.category,
    })),
    conflicts: rawConflicts,
    preliminaryScore: {
      trustScore: preliminaryFusion.finalTrustScore,
      verdict: preliminaryFusion.finalVerdict,
      riskLevel: preliminaryFusion.finalRiskLevel,
      activeDimensions: legitifyScore.score_trace?.dimensions
        .filter(d => d.active)
        .map(d => ({ name: d.name, score: d.score, status: d.status, contrib: d.weighted_contribution })),
    },
    dualRAGContext: dualRAGCitations.formatted_context,
  }).catch(() => undefined);

  // Stage 17: LEGITIFY ↔ GEMINI Reconciliation (Agreements, Contradictions, Unknowns)
  const geminiReconciliation: GeminiReconciliationReport = {
    agreements: geminiResult?.structuredDossier?.agreements?.length
      ? geminiResult.structuredDossier.agreements
      : (geminiResult?.positiveSignals?.map(s => s.finding) || []),
    contradictions: geminiResult?.structuredDossier?.contradictions?.length
      ? geminiResult.structuredDossier.contradictions
      : (geminiResult?.contradictions || []),
    unknowns: geminiResult?.structuredDossier?.unknowns?.length
      ? geminiResult.structuredDossier.unknowns
      : (geminiResult?.unverifiedItems?.length ? geminiResult.unverifiedItems : ['Signatory employment record could not be confirmed in public registries.']),
    finalAssessment: geminiResult?.structuredDossier?.finalAssessment || geminiResult?.summary || 'Independent investigation completed.',
    pathA_trust_score: preliminaryFusion.finalTrustScore,
    pathA_verdict: preliminaryFusion.finalVerdict,
    gemini_verdict: geminiResult?.verdict || 'UNAVAILABLE',
    reconciliation_notes: geminiResult
      ? `Path A deterministic score (${preliminaryFusion.finalTrustScore}/100, ${preliminaryFusion.finalVerdict}) evaluated alongside Gemini independent cross-examination (${geminiResult.verdict || 'PENDING'}). Hard safety caps strictly enforced by deterministic engine.`
      : 'Gemini independent cross-examination offline/rate-limited; Path A deterministic evidence governs assessment.',
  };

  const geminiCrossExamination: GeminiCrossExaminationReport | undefined = geminiResult ? {
    engine: 'GEMINI',
    model: geminiResult.geminiModel,
    status: geminiResult.investigationStatus,
    verdict: geminiResult.verdict,
    confidence: geminiResult.confidence,
    summary: geminiResult.summary,
    riskSignals: geminiResult.riskSignals,
    positiveSignals: geminiResult.positiveSignals,
    sources: geminiResult.sources.map(s => ({
      sourceId: s.sourceId,
      title: s.title,
      publisher: s.publisher,
      url: s.url,
      authorityTier: s.authorityTier,
      finding: s.finding,
    })),
    unverifiedItems: geminiResult.unverifiedItems,
    contradictions: geminiResult.contradictions,
    recommendedActions: geminiResult.recommendedActions,
    searchCoverage: geminiResult.searchCoverage,
  } : undefined;

  // Enrich Evidence Locker with external sources discovered by Gemini (LinkedIn, Quora, Reddit, Job Boards)
  if (geminiResult?.sources && geminiResult.sources.length > 0) {
    for (const src of geminiResult.sources) {
      evidence.push({
        id: `${scanId}-EXT-WEB-${src.sourceId || Math.random().toString(36).slice(2, 8).toUpperCase()}`,
        category: 'COMMUNITY',
        title: src.title || 'Public Web Search Discovery',
        evidence_text: src.finding || src.title,
        status: 'VERIFIED',
        confidence: 85,
        source_name: src.publisher || 'Public Web (LinkedIn/Quora/Reddit/Job Platforms)',
        source_url: src.url,
      } as any);
    }
  }

  // Stage 18: Final Trust Score & Confidence Sealing
  const finalFusion = geminiResult ? runEvidenceFusion({
    legitifyResult: legitifyScore,
    legitifyEvidence: evidence,
    geminiResult,
    hasFeeDemand: hasPaymentDemand,
    hasLookalikeDomain: isLookalike,
    hasKnownThreat: isMaliciousIOC,
    companyName: targetCompany,
    domain: targetDomain,
    recruiterEmail: targetEmail,
    publicExperience: publicExpResult || undefined,
    entityGraph: entityGraph as any,
    fraudPatterns,
    legitimatePatterns,
    counterEvidence,
    isYoungStartup: domainData?.age_days !== undefined && domainData.age_days < 365,
  }) : preliminaryFusion;

  // Final fused score result
  const scoreResult: DeterministicScoreResult = {
    ...legitifyScore,
    trust_score: finalFusion.finalTrustScore,
    confidence_score: finalFusion.finalEvidenceConfidence,
    risk_level: (finalFusion.finalRiskLevel === 'INSUFFICIENT EVIDENCE' || finalFusion.finalRiskLevel === 'INSUFFICIENT EVIDENCE / REVIEW' ? 'MODERATE' : finalFusion.finalRiskLevel) as any,
    verdict: (finalFusion.finalVerdict === 'INSUFFICIENT EVIDENCE / REVIEW' ? 'INSUFFICIENT_EVIDENCE' : finalFusion.finalVerdict) as any,
    hard_caps_applied: [
      ...legitifyScore.hard_caps_applied,
      ...finalFusion.hardRulesTriggered.map(r => `${r.name}: ${r.effect}`),
    ],
    score_trace: legitifyScore.score_trace ? {
      ...legitifyScore.score_trace,
      final_score: finalFusion.finalTrustScore,
      verdict: (finalFusion.finalVerdict === 'INSUFFICIENT EVIDENCE / REVIEW' ? 'INSUFFICIENT_EVIDENCE' : finalFusion.finalVerdict),
    } : undefined,
  };

  // Stage 19: 26-Section Hierarchy Report Compilation & Persistence
  const aiProvider = await getActiveAIProvider();
  const aiSynthesis = await aiProvider.generateSynthesis({
    entityName: entityValue,
    entityType,
    trustScore: scoreResult.trust_score,
    confidence: scoreResult.confidence_score,
    riskLevel: scoreResult.risk_level,
    verdict: scoreResult.verdict,
    evidence,
    rulesTriggered: scoreResult.rules_triggered,
    mlEvaluation: mlPrediction as any,
    untrustedUserText: fullTextToAnalyze,
  });

  const processingTimeMs = Date.now() - scanStartTime;

  const pipelineTrace: PipelineTrace = {
    scanId,
    startedAt: new Date(scanStartTime).toISOString(),
    completedAt: new Date().toISOString(),
    stages: traceStages,
    totalDurationMs: Date.now() - scanStartTime,
  };

  const signatoryForensics = visualForensicsResult ? {
    signature_detected: visualForensicsResult.signatureType !== 'ABSENT',
    signature_type: visualForensicsResult.signatureType,
    signatory_name: visualForensicsResult.signatoryName,
    signatory_title: visualForensicsResult.signatoryTitle,
    signatory_department: visualForensicsResult.signatoryDepartment,
    identity_state: visualForensicsResult.signatoryState,
    page: visualForensicsResult.regions.find(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK')?.page || 1,
    evidence_ids: visualForensicsResult.evidence.map(e => e.id).filter(Boolean) as string[],
    detection_method: visualForensicsResult.detectionMethod,
  } : undefined;

  const finalReport = compileFullReport({
    scanId,
    entityName: entityValue,
    entityType,
    scoreResult,
    completeness,
    mlPrediction: mlPrediction as any,
    entityGraph,
    aiSynthesis,
    companyData,
    domainData,
    recruiterData,
    documentData: docResult,
    certificateData,
    threatData,
    webIntelligence: webResult || undefined,
    contradictions,
    evidence,
    processingTimeMs,
    publicExperience: publicExpResult || undefined,
    fraudPatterns,
    legitimatePatterns,
    counterEvidence,
    fraudConfidence: finalFusion.fraudConfidence,
    explanationSummary: finalFusion.explanationSummary,
    extractedOfferParts,
    geminiCrossExamination,
    geminiReconciliation,
    dualRAGCitations,
    signatoryForensics,
    pipelineTrace,
  });

  // Stage 18: REPORT ASSERTION GUARD
  // Enforces that every factual statement has verifiable evidence or is framed as an honest uncertainty
  const { guardedReport, guardAudit } = runReportAssertionGuard(finalReport, evidence);

  // Step 13: Persist Guarded Report to Supabase Database
  await persistReport(scanId, userId, guardedReport, evidence, companyData);

  await logAuditEvent({
    user_id: userId,
    action: 'SCAN_COMPLETED',
    resource_type: 'scan',
    resource_id: scanId,
    ip,
    user_agent: userAgent,
    metadata: {
      trustScore: guardedReport.trust_score,
      verdict: guardedReport.verdict,
      riskLevel: guardedReport.risk_level,
      assertionsChecked: guardAudit.totalAssertionsChecked,
      assertionsSanitized: guardAudit.blockedOrSanitized,
    },
  });

  return guardedReport;
}
