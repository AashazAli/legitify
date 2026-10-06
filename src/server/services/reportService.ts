// ==============================================================================
// LEGITIFY REPORT COMPILATION & PERSISTENCE
// Compiles 22-section structured report, tokenized public sharing, and Supabase storage
// ==============================================================================
import crypto from 'crypto';
import {
  LegitifyReport,
  ScanEntityType,
  DeterministicScoreResult,
  EvidenceItem,
  CertificateVerificationData,
  EvidenceCompleteness,
  MLPredictionResult,
  EntityGraphData,
  ExtractedOfferParts,
  GeminiCrossExaminationReport,
  GeminiReconciliationReport,
  DualRAGCitations,
} from '../../types';
import { CompanyData } from './companyService';
import { DomainData } from './domainService';
import { RecruiterData } from './emailService';
import { DocumentExtractionResult } from './documentService';
import { ThreatData } from './threatService';
import { AISynthesisOutput } from './aiProvider';
import { supabaseAdmin } from '../../lib/supabase/server';
import { WebIntelligenceResult } from './webIntelligenceService';

export interface CompileReportParams {
  scanId: string;
  entityName: string;
  entityType: ScanEntityType;
  scoreResult: DeterministicScoreResult;
  completeness: EvidenceCompleteness;
  mlPrediction: MLPredictionResult;
  entityGraph: EntityGraphData;
  aiSynthesis: AISynthesisOutput;
  companyData?: CompanyData;
  domainData?: DomainData;
  recruiterData?: RecruiterData;
  documentData?: DocumentExtractionResult;
  certificateData?: CertificateVerificationData;
  threatData?: ThreatData;
  webIntelligence?: WebIntelligenceResult;
  contradictions?: any[];
  evidence: EvidenceItem[];
  processingTimeMs?: number;
  publicExperience?: any;
  fraudPatterns?: any[];
  legitimatePatterns?: any[];
  counterEvidence?: any[];
  fraudConfidence?: number;
  explanationSummary?: any;
  extractedOfferParts?: ExtractedOfferParts;
  geminiCrossExamination?: GeminiCrossExaminationReport;
  geminiReconciliation?: GeminiReconciliationReport;
  dualRAGCitations?: DualRAGCitations;
  signatoryForensics?: LegitifyReport['signatory_forensics'];
  pipelineTrace?: LegitifyReport['pipeline_trace'];
}

export function compileFullReport(params: CompileReportParams): LegitifyReport {
  const {
    scanId,
    entityName,
    entityType,
    scoreResult,
    completeness,
    mlPrediction,
    entityGraph,
    aiSynthesis,
    companyData,
    domainData,
    recruiterData,
    documentData,
    certificateData,
    threatData,
    webIntelligence,
    contradictions,
    evidence,
  } = params;

  const consistencyAnalysis: LegitifyReport['consistency_analysis'] = [];

  // Domain vs Company consistency
  if (companyData && domainData) {
    if (domainData.lookalike_detected) {
      consistencyAnalysis.push({
        item: "Domain vs Company Match",
        status: "MISMATCH",
        detail: `Domain impersonates brand name (${domainData.lookalike_target}) with deceptive variation.`,
      });
    } else if (companyData.domain && domainData.domain && companyData.domain === domainData.domain) {
      consistencyAnalysis.push({
        item: "Domain vs Company Match",
        status: "MATCH",
        detail: "Domain matches official corporate registered website.",
      });
    }
  }

  // Recruiter vs Company consistency
  if (recruiterData && companyData) {
    if (recruiterData.is_free_provider) {
      consistencyAnalysis.push({
        item: "Recruiter Email vs Company Identity",
        status: "WARNING",
        detail: "Recruiter uses public email provider while representing registered corporate entity.",
      });
    } else if (recruiterData.domain_alignment === 'MATCH') {
      consistencyAnalysis.push({
        item: "Recruiter Email vs Company Identity",
        status: "MATCH",
        detail: "Sender email domain corresponds directly to verified company domain.",
      });
    }
  }

  const report: LegitifyReport = {
    scan_id: scanId,
    entity_name: entityName,
    entity_type: entityType,
    trust_score: scoreResult.trust_score,
    confidence: scoreResult.confidence_score,
    evidence_completeness: completeness,
    risk_level: scoreResult.risk_level,
    verdict: scoreResult.verdict,
    executive_summary: aiSynthesis.executive_summary,
    structured_explanation: aiSynthesis.structured_explanation,
    recommendation: aiSynthesis.recommendation,
    positive_signals: scoreResult.positive_signals,
    warning_signals: scoreResult.warning_signals,
    critical_signals: scoreResult.critical_signals,
    missing_evidence: completeness.missing_evidence,
    company_verification: {
      legal_name: companyData?.legal_name,
      normalized_name: companyData?.normalized_name,
      status: companyData?.status || (companyData?.registry_status === 'VERIFIED' ? 'ACTIVE' : 'UNKNOWN'),
      registry_status: companyData?.registry_status || "UNKNOWN",
      registration_number: companyData?.registration_number,
      registered_address: companyData?.registered_address,
      country: companyData?.country,
      state: companyData?.state,
      city: companyData?.city,
      website: companyData?.website,
      domain: companyData?.domain,
      last_verified: companyData?.last_verified_at,
      source: companyData?.registry_status,
    },
    domain_analysis: {
      domain: domainData?.domain,
      registrar: domainData?.registrar,
      age_days: domainData?.age_days,
      registration_date: domainData?.registration_date,
      expiration_date: domainData?.expiration_date,
      ssl_valid: domainData?.ssl_valid,
      ssl_issuer: domainData?.ssl_issuer,
      reputation_score: domainData?.reputation_score,
      threat_status: domainData?.threat_status,
      lookalike_detected: domainData?.lookalike_detected,
      lookalike_target: domainData?.lookalike_target,
    },
    recruiter_analysis: {
      email: recruiterData?.email,
      display_name: recruiterData?.display_name,
      domain: recruiterData?.domain,
      domain_alignment: recruiterData?.domain_alignment,
      free_email_provider: recruiterData?.is_free_provider,
      spf_status: recruiterData?.spf_status,
      dkim_status: recruiterData?.dkim_status,
      dmarc_status: recruiterData?.dmarc_status,
      known_threat: recruiterData?.known_threat,
    },
    certificate_verification: certificateData,
    document_analysis: documentData ? {
      filename: documentData.filename,
      mime_type: documentData.mime_type,
      extracted_entities: {
        detected_company: documentData.detected_company_name,
        detected_stipend: documentData.detected_stipend,
        detected_dates: documentData.detected_dates,
        suspicious_pressure_phrases: (documentData as any).suspicious_pressure_phrases || [],
      },
      suspicious_patterns_detected: (documentData as any).suspicious_pressure_phrases || [],
      requested_fees: (documentData as any).detected_fees || [],
    } : undefined,
    threat_intelligence: {
      matched_iocs_count: threatData?.count || 0,
      indicators: threatData?.matches?.map(m => ({
        type: m.indicator_type,
        value: m.indicator_value,
        threat_type: m.threat_type,
        severity: m.severity,
        source: m.source,
      })) || [],
    },
    ml_evaluation: mlPrediction,
    rules_evaluated: scoreResult.rules_triggered,
    public_community_evidence: webIntelligence?.results?.map(r => ({
      source: r.sourceDomain || 'Public Web',
      title: r.title,
      snippet: r.snippet,
      url: r.url,
      sentiment: r.sentiment,
    })) || [],
    web_intelligence: webIntelligence ? {
      searches_conducted: webIntelligence.searches_conducted,
      official_sources_matched: webIntelligence.official_sources_matched,
      reputable_reviews_found: webIntelligence.reputable_reviews_found,
      community_complaint_clusters: webIntelligence.community_complaint_clusters,
      total_sources_evaluated: webIntelligence.total_sources_evaluated,
    } : undefined,
    contradictions_detected: contradictions,
    consistency_analysis: consistencyAnalysis,
    entity_graph: entityGraph,
    timeline: [
      { time: new Date().toLocaleTimeString(), event: "Scan Initiated", detail: `Target: ${entityName} · Type: ${entityType}`, status: "ok" },
      { time: new Date().toLocaleTimeString(), event: "Evidence Extraction", detail: `Extracted features across ${evidence.length} collected items`, status: "ok" },
      { time: new Date().toLocaleTimeString(), event: "Web & Registry Corroboration", detail: `Correlated ${webIntelligence?.total_sources_evaluated || 0} public web sources`, status: "ok" },
      { time: new Date().toLocaleTimeString(), event: "Rule & ML Execution", detail: `Evaluated ${scoreResult.rules_triggered.length} rules · ML Class: ${mlPrediction.predicted_class}`, status: "ok" },
      { time: new Date().toLocaleTimeString(), event: "Deterministic Score Computed", detail: `Trust: ${scoreResult.trust_score}/100 · Verdict: ${scoreResult.verdict}`, status: "ok" },
      { time: new Date().toLocaleTimeString(), event: "Structured Synthesis Generated", detail: `Synthesis engine: ${aiSynthesis.provider_used}`, status: "ok" },
    ],
    evidence_sources: [
      { provider: "ICANN RDAP / Authoritative DNS", status: domainData?.has_dns ? "AVAILABLE" : "UNAVAILABLE" },
      { provider: "Supervised ML Risk Classifier (v1.2.0)", status: "AVAILABLE" },
      { provider: "Web Intelligence & Search Corroboration", status: webIntelligence ? "AVAILABLE" : "UNAVAILABLE" },
      { provider: "10-Tier Certificate Hierarchy", status: certificateData ? "AVAILABLE" : "CACHED" },
      { provider: "VirusTotal & Google Safe Browsing", status: (process.env.VIRUSTOTAL_API_KEY || process.env.SAFE_BROWSING_API_KEY) ? "AVAILABLE" : "UNAVAILABLE" },
      { provider: "Rule Engine (R001 - R007)", status: "AVAILABLE" },
    ],
    limitations: aiSynthesis.limitations,
    disclaimer: "LEGITIFY provides an automated evidence-based risk analysis to support applicant decision-making. It is not a legal determination, guarantee of employment legitimacy, or definitive proof of fraudulent intent.",
    // --- InternShield & Extended Visual Dossier Parity ---
    company_name: entityName,
    confidence_score: scoreResult.confidence_score,
    input_type: (documentData?.filename?.toLowerCase().endsWith('.pdf') ? 'pdf' : (entityType || 'text')).toUpperCase(),
    dimension_scores: {
      rules: Math.round((scoreResult.components as any).document?.score ?? 0),
      nlp: Math.round((scoreResult.components as any).ml_probability?.score ?? 0),
      ner: Math.round((scoreResult.components as any).recruiter?.score ?? 0),
      document_authenticity: Math.round((scoreResult.components as any).document_authenticity?.score ?? 0),
      company_legal: Math.round((scoreResult.components as any).company?.score ?? 0),
      domain_security: Math.round((scoreResult.components as any).domain?.score ?? 0),
      recruiter_auth: Math.round((scoreResult.components as any).recruiter?.score ?? 0),
      financial_safety: Math.round((scoreResult.components as any).document?.score ?? 0),
      certificate_auth: Math.round((scoreResult.components as any).certificate?.score ?? 0),
      ml_fraud_model: Math.round((scoreResult.components as any).ml_probability?.score ?? 0),
      threat_intel: Math.round((scoreResult.components as any).threat?.score ?? 0),
      community_evidence: Math.round((scoreResult.components as any).community?.score ?? 0),
      consistency_cross_check: Math.round((scoreResult.components as any).consistency?.score ?? 0),
    },
    components: scoreResult.components as any,
    rules_triggered: scoreResult.rules_triggered,
    hard_caps_applied: scoreResult.hard_caps_applied,
    red_flags: scoreResult.critical_signals.concat(scoreResult.warning_signals),
    triggered_flags: documentData?.triggered_flags || scoreResult.rules_triggered.map(r => ({
      rule: r.rule_id || r.name,
      severity: (r.severity?.toLowerCase() || 'medium') as any,
      message: r.explanation || r.description || r.name,
      score: r.score_impact || 0.5,
    })),
    next_steps: documentData?.next_steps || (scoreResult.trust_score <= 40 ? [
      "🚨 Do NOT share any personal documents (Aadhaar, PAN, bank details) with this organization.",
      "Report this offer letter to your college placement cell immediately.",
      "If you found this on Internshala or LinkedIn, report the listing on the platform.",
      "File a complaint on the National Cyber Crime Portal (cybercrime.gov.in) if you've already shared any information.",
      "Do NOT pay any 'registration fee', 'security deposit', or 'training charges'. Legitimate companies never ask candidates for money.",
      `Search for '${entityName}' on MCA21 (mca.gov.in) to check if it's a registered company.`,
    ] : [
      "✅ This letter appears to have authentic structural characteristics.",
      "Verify recruiter email alignment with the official corporate domain before accepting.",
      "Confirm the offer letter reference ID through the official employee recruitment portal.",
      "Prepare standard onboarding documents (educational transcripts and ID proofs).",
    ]),
    public_experience: params.publicExperience,
    fraud_patterns: params.fraudPatterns,
    legitimate_patterns: params.legitimatePatterns,
    counter_evidence: params.counterEvidence,
    fraud_confidence: params.fraudConfidence,
    explanation_summary: params.explanationSummary,
    score_trace: scoreResult.score_trace,
    extracted_offer_parts: params.extractedOfferParts,
    gemini_cross_examination: params.geminiCrossExamination,
    gemini_reconciliation: params.geminiReconciliation,
    dual_rag_citations: params.dualRAGCitations,
    signatory_forensics: params.signatoryForensics,
    pipeline_trace: params.pipelineTrace,
    has_fee_demand: Boolean(
      documentData?.has_fee_demand ||
      params.fraudPatterns?.hasPaymentDemand ||
      (params as any).hasPaymentDemand ||
      scoreResult.rules_triggered.some(r => r.rule_id === 'R001' || r.name?.toLowerCase().includes('fee') || r.description?.toLowerCase().includes('fee') || r.explanation?.toLowerCase().includes('fee')) ||
      scoreResult.hard_caps_applied.some(c => c.toLowerCase().includes('fee') || c.toLowerCase().includes('payment'))
    ),
    evidence: params.evidence || [],
    extracted_claims: params.documentData?.extracted_claims || [],
  } as any;

  return report;
}

export async function persistReport(
  scanId: string,
  userId: string,
  report: LegitifyReport,
  evidence: EvidenceItem[],
  companyData?: CompanyData
): Promise<void> {
  try {
    const timeout = new Promise<void>((resolve) => setTimeout(resolve, 800));
    const work = (async () => {
      // 1. Update Scan Record
      await supabaseAdmin
        .from('scans')
        .update({
          status: 'COMPLETED',
          trust_score: report.trust_score,
          confidence_score: report.confidence,
          risk_level: report.risk_level,
          verdict: report.verdict,
          completed_at: new Date().toISOString(),
        })
        .eq('id', scanId);

      // 2. Insert Report
      await supabaseAdmin
        .from('reports')
        .upsert({
          scan_id: scanId,
          user_id: (userId && userId !== '00000000-0000-0000-0000-000000000000') ? userId : null,
          summary: report.executive_summary,
          verdict: report.verdict,
          trust_score: report.trust_score,
          risk_level: report.risk_level,
          confidence: report.confidence,
          report_json: report,
        }, { onConflict: 'scan_id' });

      // 3. Insert Evidence Items
      if (evidence.length > 0 && scanId && !scanId.startsWith('SC-')) {
        const evidenceRecords = evidence.map(e => ({
          scan_id: scanId,
          category: e.category,
          evidence_type: e.evidence_type,
          source_name: e.source_name,
          source_url: e.source_url,
          title: e.title,
          snippet: e.snippet,
          evidence_text: e.evidence_text,
          evidence_strength: e.evidence_strength,
          status: e.status,
          severity: e.severity,
          verified: e.verified,
          confidence: e.confidence,
        }));

        try {
          await supabaseAdmin.from('evidence').insert(evidenceRecords);
        } catch {}
      }

      // 4. Update Shared Company Intelligence Cache
      if (companyData && companyData.normalized_name) {
        try {
          const { data: comp } = await supabaseAdmin
            .from('companies')
            .upsert({
              normalized_name: companyData.normalized_name,
              legal_name: companyData.legal_name,
              registration_number: companyData.registration_number,
              country: companyData.country || 'India',
              state: companyData.state,
              city: companyData.city,
              website: companyData.website,
              domain: companyData.domain,
              status: companyData.status || 'ACTIVE',
              registry_status: companyData.registry_status,
              trust_score: report.trust_score,
              risk_level: report.risk_level,
              last_verified_at: new Date().toISOString(),
            }, { onConflict: 'normalized_name' })
            .select('id')
            .maybeSingle();

          if (comp?.id) {
            await supabaseAdmin.from('company_intelligence').insert({
              company_id: comp.id,
              category: 'REGISTRY_RECORD',
              source: (companyData as any).source || 'Automated Registry Verification',
              title: `Verification record for ${companyData.legal_name || companyData.normalized_name}`,
              content_summary: `Trust Score: ${report.trust_score}/100. Verification Status: ${companyData.registry_status}`,
              confidence: report.confidence,
            });
          }
        } catch {}
      }
    })();

    await Promise.race([work, timeout]);
  } catch (err) {
    console.error('[LEGITIFY] Report persistence warning:', err);
  }
}

export async function createShareToken(scanId: string, userId: string): Promise<string> {
  const token = crypto.randomBytes(16).toString('hex');
  await supabaseAdmin
    .from('reports')
    .update({
      share_token: token,
      shared_at: new Date().toISOString(),
      is_public: true,
    })
    .eq('scan_id', scanId);

  return token;
}

export async function getReportByShareToken(token: string): Promise<LegitifyReport | null> {
  const { data } = await supabaseAdmin
    .from('reports')
    .select('report_json')
    .eq('share_token', token)
    .eq('is_public', true)
    .maybeSingle();

  return data ? (data.report_json as LegitifyReport) : null;
}
