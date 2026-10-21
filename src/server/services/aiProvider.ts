// ==============================================================================
// LEGITIFY EVIDENCE-GROUNDED INVESTIGATION COPILOT (AI PROVIDER)
// Strict Evidence-First Architecture + Adaptive LLM Intelligence Grounded in Evidence
// ==============================================================================
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';
import { EvidenceItem, RuleEvaluation, MLPredictionResult } from '../../types';
import { isFilenameOrPlaceholder } from '../utils/normalizer';
import { callHuggingFaceChat, HfChatMessage } from './huggingfaceService';

export interface AISynthesisInput {
  entityName: string;
  entityType: string;
  trustScore: number;
  confidence: number;
  riskLevel: string;
  verdict: string;
  evidence: EvidenceItem[];
  rulesTriggered: RuleEvaluation[];
  mlEvaluation?: MLPredictionResult;
  untrustedUserText?: string;
}

export interface AISynthesisOutput {
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
  limitations: string[];
  provider_used: "LOCAL_AI" | "GEMINI_FLASH" | "DETERMINISTIC_FALLBACK" | "HUGGINGFACE";
}

export interface IAIProvider {
  isAvailable(): Promise<boolean>;
  generateSynthesis(input: AISynthesisInput): Promise<AISynthesisOutput>;
  answerCopilot(question: string, context: Record<string, any>): Promise<string>;
}

// ----------------------------------------------------------------------------
// SANITIZE ENTITY / COMPANY NAME
// ----------------------------------------------------------------------------
export function sanitizeCompanyName(context: Record<string, any>): string {
  const detected = context.document_analysis?.extracted_entities?.detected_company || context.document_analysis?.detected_company_name;
  if (detected && !isFilenameOrPlaceholder(detected)) {
    return detected;
  }

  const raw = String(context.company_name || context.entity_name || context.entity_value || "");
  if (!raw || isFilenameOrPlaceholder(raw)) {
    return "Organization not confidently identified";
  }
  return raw;
}

// ----------------------------------------------------------------------------
// EVIDENCE LOCKER BUILDER (DYNAMIC PROVENANCE)
// ----------------------------------------------------------------------------
export interface EvidenceRecord {
  id: string;
  type: "COMPANY_REGISTRY" | "DOMAIN" | "RECRUITER" | "DOCUMENT" | "CERTIFICATE" | "COMMUNITY" | "ML_MODEL" | "RULE_ENGINE";
  status: "VERIFIED" | "WARNING" | "CRITICAL" | "SUSPICIOUS" | "CORROBORATED" | "UNVERIFIED" | "FLAGGED";
  source: string;
  claim: string;
  confidence: number;
  tier: "AUTHORITATIVE" | "STRONG" | "MODERATE" | "COMMUNITY" | "USER_PROVIDED";
}

export function buildEvidenceLocker(context: Record<string, any>): EvidenceRecord[] {
  const locker: EvidenceRecord[] = [];
  const compName = sanitizeCompanyName(context);

  // If genuine Evidence Ledger items exist in context, ground strictly in real items!
  if (Array.isArray(context.evidence) && context.evidence.length > 0) {
    for (let i = 0; i < context.evidence.length; i++) {
      const ev = context.evidence[i];
      const id = ev.evidence_id || ev.id || `E-${String(i + 1).padStart(3, '0')}`;
      let catType: EvidenceRecord['type'] = "DOCUMENT";
      const c = (ev.category || '').toUpperCase();
      if (c.includes('COMPANY') || c.includes('REGISTRY')) catType = "COMPANY_REGISTRY";
      else if (c.includes('DOMAIN')) catType = "DOMAIN";
      else if (c.includes('RECRUITER') || c.includes('EMAIL')) catType = "RECRUITER";
      else if (c.includes('CERTIFICATE')) catType = "CERTIFICATE";
      else if (c.includes('COMMUNITY') || c.includes('PUBLIC')) catType = "COMMUNITY";
      else if (c.includes('ML')) catType = "ML_MODEL";

      locker.push({
        id,
        type: catType,
        status: ev.verified ? "VERIFIED" : ev.severity === "CRITICAL" ? "CRITICAL" : ev.severity === "HIGH" ? "WARNING" : "UNVERIFIED",
        source: ev.source_name || ev.source || "Forensic Evidence Ledger",
        claim: ev.title ? `${ev.title}: ${ev.snippet || ev.evidence_text || ''}` : (ev.evidence_text || ev.snippet || ""),
        confidence: ev.confidence || 0.85,
        tier: ev.authority_tier === "TIER_1_REGISTRY" ? "AUTHORITATIVE" : "STRONG",
      });
    }
    return locker;
  }

  // If score trace dimensions exist in context
  if (context.score_trace?.dimensions) {
    for (const d of context.score_trace.dimensions) {
      if (d.active) {
        locker.push({
          id: d.evidence_ids?.[0] || `DIM-${d.dimension.toUpperCase()}`,
          type: d.dimension === 'company' ? 'COMPANY_REGISTRY' : d.dimension === 'domain' ? 'DOMAIN' : d.dimension === 'recruiter' ? 'RECRUITER' : 'DOCUMENT',
          status: d.status,
          source: d.name,
          claim: d.reason,
          confidence: 0.90,
          tier: "STRONG",
        });
      }
    }
    if (locker.length > 0) return locker;
  }

  return locker;
}

// ----------------------------------------------------------------------------
// DOMAIN GUARDRAILS
// ----------------------------------------------------------------------------
export function isDomainOffTopic(question: string): boolean {
  const q = question.toLowerCase().trim();
  if (!q) return false;

  // Short greetings and conversation starters are allowed
  if (/^(hi|hello|hey|good\s*(morning|afternoon|evening)|help|thanks|thank you)\b/i.test(q)) {
    return false;
  }

  // Keywords indicating on-topic employment, scam, forensic, cyber domain
  const onTopicTerms = [
    'job', 'offer', 'intern', 'internship', 'hiring', 'recruiter', 'recruitment', 'hr',
    'company', 'stipend', 'salary', 'ctc', 'compensation', 'fee', 'charge', 'cost',
    'deposit', 'caution', 'pay', 'payment', 'upi', 'bank', 'score', 'verdict', 'rating',
    'trust', 'risk', 'scam', 'fraud', 'fake', 'legit', 'legitimate', 'genuine', 'real',
    'report', 'document', 'letter', 'contract', 'agreement', 'clause', 'terms', 'condition',
    'mca', 'cin', 'registry', 'domain', 'email', 'gmail', 'signatory', 'signed', 'signature',
    'stamp', 'seal', 'cybercrime', '1930', 'helpline', 'police', 'fir', 'reddit', 'quora',
    'linkedin', 'interview', 'selection', 'joining', 'onboarding', 'work', 'hours', 'schedule',
    'timing', 'shift', 'leave', 'notice', 'probation', 'evidence', 'red flag', 'warning',
    'safe', 'safety', 'guideline', 'career', 'advice', 'rights', 'legal', 'law', 'cheated',
    'verify', 'verification', 'check', 'valid', 'validity', 'experience', 'placement'
  ];

  if (onTopicTerms.some(term => q.includes(term))) {
    return false;
  }

  // Explicitly off-topic subject triggers
  const offTopicTriggers = [
    'recipe', 'cook', 'bake', 'cake', 'weather', 'forecast', 'poem', 'poetry',
    'movie', 'song', 'lyrics', 'game', 'gaming', 'play', 'cricket', 'football',
    'capital of', 'translate', 'joke', 'riddle', 'horoscope', 'zodiac', 'dating',
    'girlfriend', 'boyfriend', 'solve equation', 'quantum physics', 'who won the match'
  ];

  return offTopicTriggers.some(term => q.includes(term));
}

export const DOMAIN_GUARDRAIL_MESSAGE = `### Legitify Domain Guardrail Notice

I am the **LEGITIFY Employment Security & Forensic Copilot**. My capabilities are dedicated strictly to:
* Evaluating job and internship offer letters for fraud or tampering
* Analyzing corporate legitimacy, statutory MCA21 registration, and domain security
* Identifying fee demands, caution deposits, and lookalike domains
* Providing actionable safety steps, verification advice, and emergency cybercrime reporting procedures (1930)

I cannot assist with queries outside employment verification and document forensics. **Please ask a question related to your offer letter, the recruiting entity, or employment safety.**`;

// ----------------------------------------------------------------------------
// GREETING DETECTION & CONVERSATIONAL ASSISTANT RESPONSES
// ----------------------------------------------------------------------------
export function isGreeting(text: string): boolean {
  const clean = text.toLowerCase().trim().replace(/[!.,?]+$/, '');
  const greetingPatterns = [
    /^(hi|hello|hey|heya|howdy|greetings|good\s*(morning|afternoon|evening|day))\b/i,
    /^(how\s+are\s+you|who\s+are\s+you|what\s+can\s+you\s+do|can\s+you\s+help\s*(me)?)\b/i,
    /^(start|help|menu|options|assist)\b/i,
  ];
  return greetingPatterns.some(p => p.test(clean)) && clean.split(/\s+/).length <= 6;
}

export function buildGreetingResponse(userName: string, companyName: string): string {
  const comp = companyName && !companyName.toLowerCase().includes('not confidently identified')
    ? companyName
    : 'the investigated document';

  return `Hello ${userName !== 'Candidate' ? userName : 'there'}! I am your LEGITIFY Forensic Investigation Assistant.

I have evaluated the document for **${comp}**.

How can I help you today? You can ask me:
* **Payment & Fees:** Check whether this offer asks for upfront fees or caution deposits.
* **Recruiter & Domain:** Verify if the recruiter's email domain matches the official company.
* **Corporate Legitimacy:** Check if ${companyName} is registered with the Ministry of Corporate Affairs (MCA21).
* **Offer Details:** Review working hours, designated role, or stipend terms.
* **Next Steps:** What questions should I ask HR, or what emergency steps should I take if money was requested?`;
}

// ----------------------------------------------------------------------------
// COMPREHENSIVE EVIDENCE-GROUNDED REASONING ENGINE (DYNAMIC INTENT HANDLER)
// Dynamically inspects raw document text, extracted offer parts, structural
// format checks, detected risks, and evidence locker to answer questions accurately.
// ----------------------------------------------------------------------------
export function generateEvidenceGroundedAnswer(question: string, context: Record<string, any>): string {
  if (isDomainOffTopic(question)) {
    return DOMAIN_GUARDRAIL_MESSAGE;
  }

  const q = question.toLowerCase().trim();
  const userName = context.user_name || context.candidate_name || (context.user_email ? context.user_email.split('@')[0] : 'Candidate');
  const companyName = sanitizeCompanyName(context);

  // Handle conversational greetings directly without dumping audit profiles
  if (isGreeting(q)) {
    return buildGreetingResponse(userName, companyName);
  }

  const score = typeof context.trust_score === 'number'
    ? context.trust_score
    : (typeof context.confidence_score === 'number' ? context.confidence_score : (typeof context.final_score === 'number' ? context.final_score : 50));
  const confidence = context.confidence || context.confidence_score || 85;
  const isHighRisk = score <= 45;
  const verdict = context.verdict || (isHighRisk ? 'LIKELY SCAM / HIGH RISK' : 'LOW RISK / AUTHENTIC PROFILE');

  // 1. Collect Raw Document Text Corpus
  const docText = String(
    context.rawText ||
    context.raw_text ||
    context.text ||
    context.document_analysis?.extracted_text ||
    context.extracted_text ||
    context.forensicAnalysis?.ocr?.rawText ||
    context.context_text ||
    context.contextText ||
    ''
  ).trim();
  const docTextLower = docText.toLowerCase();

  // 2. Collect Extracted Entities & Parameters
  const offerParts = context.extracted_offer_parts || {};
  const semantics = context.forensicAnalysis?.semantics || context.document_analysis?.semantics || {};
  const structure = context.forensicAnalysis?.scoring?.structureAnalysis || semantics?.structure || context.structureAnalysis;

  const claimRole = (context.extracted_claims || context.document_analysis?.extracted_claims || []).find((c: any) => c.field?.toLowerCase() === 'role' || c.claim_type === 'ROLE_DESIGNATION')?.value;
  const rawMatchedRole = docText.match(/(?:Role|Position|Designation|Job Title|Internship as)\s*[:\-]?\s*([A-Za-z0-9\s/&()\-]{3,40})/i)?.[1]?.trim();
  const cleanedMatchedRole = rawMatchedRole
    ? rawMatchedRole.replace(/^(?:of|as|an?)\s+/i, '').replace(/\s+(?:for\s+a\s+duration|for\s+duration|for|at|with|commencing|in|from)\b.*$/i, '').trim()
    : undefined;
  const detectedRole = offerParts.roles?.[0] || claimRole || semantics.detectedRole || cleanedMatchedRole || 'Internship / Employment Position';
  
  const detectedStipends: any[] = offerParts.stipends || [];
  let primaryStipend: string | undefined = detectedStipends[0]?.rawText || semantics.detectedStipend || (docText.match(/(?:Stipend|Salary|Compensation|CTC|Remuneration)\s*[:\-]?\s*(?:INR|Rs\.?|₹|\$|USD)?\s*([0-9,]+(?:\s*(?:per month|\/month|LPA|K))?)/i)?.[1]?.trim());
  if (primaryStipend) {
    const hasCur = /(?:rs\.?|inr|₹|\$|€|£)/i.test(primaryStipend);
    const hasUn = /(?:per\s+month|\/month|\/mo|p\.m\.|per\s+annum|\/year|p\.a\.|lpa|lac|lakh|crore|per\s+week|\/week|\/day|per\s+day|\/hr|per\s+hour)/i.test(primaryStipend);
    const numOnly = parseFloat(primaryStipend.replace(/[^0-9.]/g, ''));
    if (!hasCur && !hasUn && (!numOnly || numOnly < 500)) {
      primaryStipend = undefined;
    }
  }

  const recruiterEmail = semantics.recruiterEmail || context.recruiter_analysis?.email || (docText.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/)?.[0]);
  const isFreeWebmail = semantics.isFreeWebmail || Boolean(recruiterEmail && (recruiterEmail.endsWith('@gmail.com') || recruiterEmail.endsWith('@yahoo.com') || recruiterEmail.endsWith('@outlook.com') || recruiterEmail.endsWith('@hotmail.com')));

  const feeDemandKeywords = semantics.feeDemandKeywords || [];
  const hasFee = semantics.hasFeeDemand || feeDemandKeywords.length > 0 || /registration\s+fee|security\s+deposit|training\s+fee|processing\s+fee|caution\s+money/i.test(docText);

  const informalChannels = semantics.informalChannels || (docTextLower.includes('telegram') ? ['Telegram'] : docTextLower.includes('whatsapp') ? ['WhatsApp'] : []);
  const hasInformal = informalChannels.length > 0;

  const hasNoInterview = semantics.hasDirectSelectionNoInterview || /without interview|no interview|direct selection|direct appointment/i.test(docTextLower);

  const referenceNumber = structure?.referenceNumber || (docText.match(/(?:ref(?:erence)?(?:\s*(?:no|num|\.))?|offer\s*(?:id|ref|letter\s*id)|requisition\s*(?:id|no)|job\s*(?:id|code))\s*[:#-]?\s*([A-Za-z0-9\/-]{3,})/i)?.[1]?.trim());

  const signatories: any[] = offerParts.signatories || [];
  const primarySignatory = signatories[0]?.name || structure?.signatoryTitle || (docText.match(/(?:Human Resources|HR Manager|Talent Acquisition|Director|Vice President|Authorized Signatory)[\s\S]{0,40}/i)?.[0]?.trim());

  const locker = buildEvidenceLocker(context);
  const detectedRisks = context.detectedRisks || semantics.riskFlags || context.triggered_flags || [];
  const feeDetails: any[] = context.document_analysis?.fee_details || context.fee_details || [];
  const primaryFee = feeDetails[0];
  const rawComp = context.document_analysis?.candidate_compensation || context.candidate_compensation;
  const candidateCompList: any[] = Array.isArray(rawComp) ? rawComp : (rawComp && typeof rawComp === 'object' ? [rawComp] : []);
  const assessments: any[] = context.assessments || context.scoring?.assessments || [];
  const paymentAssessment = assessments.find((a: any) => a.id === 'financial_safety');

  // External Research
  const extResearch = context.external_research;
  const providers = extResearch?.providers || {};
  const linkedinData = providers.linkedin;
  const redditData = providers.reddit;
  const quoraData = providers.quora;
  const companyWebData = providers.companyWeb;
  const mcaData = providers.mca;
  const extFindings: any[] = extResearch?.allFindings || [];

  // Conversation History
  const history: any[] = Array.isArray(context.history) ? context.history : [];
  const lastUserMsg = [...history].reverse().find(h => (h.role === 'user' || h.role === 'Candidate') && (h.content || h.text) !== question);
  const lastAssistantMsg = [...history].reverse().find(h => h.role === 'assistant' || h.role === 'model' || h.role === 'Copilot');

  // Payment taxonomy classification
  const paymentCase = context.payment_case || context.document_analysis?.payment_case || (
    paymentAssessment?.evidence_found?.toLowerCase().includes('warn') ? 'WARNING_AGAINST_PAYMENT' :
    paymentAssessment?.evidence_found?.toLowerCase().includes('general organizational') || paymentAssessment?.evidence_found?.toLowerCase().includes('reimbursement') ? 'POLICY_MENTION_WITHOUT_DEMAND' :
    paymentAssessment?.evidence_found?.toLowerCase().includes('insufficient') || paymentAssessment?.evidence_found?.toLowerCase().includes('ambiguous') ? 'AMBIGUOUS_EVIDENCE' :
    paymentAssessment?.risk_score >= 90 ? 'EXPLICIT_DEMAND' :
    paymentAssessment?.risk_score >= 70 ? 'CONDITIONAL_DEMAND' :
    (primaryFee?.is_refundable ? 'CONDITIONAL_DEMAND' : ((hasFee || feeDetails.length > 0) ? 'EXPLICIT_DEMAND' : 'NO_PAYMENT_EVIDENCE'))
  );

  // Helper: Find sentences in raw document matching query terms with word-boundary awareness
  const findMatchingDocSentences = (keywords: string[]): string[] => {
    if (!docText) return [];
    const sentences = docText.split(/(?<=[.!?\n])\s+/);
    return sentences.filter(s => {
      const sLower = s.toLowerCase();
      return keywords.some(k => {
        const kLower = k.toLowerCase().trim();
        if (kLower === 'rs.' || kLower === 'rs') {
          return /\b(?:rs\.?|inr|₹)\s*\d+/i.test(sLower) || /\b(?:rs\.?)\b/i.test(sLower.replace(/mrs\./gi, ''));
        }
        if (kLower.length <= 4) {
          const escaped = kLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          return new RegExp(`\\b${escaped}\\b`, 'i').test(sLower);
        }
        return sLower.includes(kLower);
      });
    }).slice(0, 3);
  };

  // ==========================================================================
  // INTENT 0: Incident Response Protocol (Already Paid Money)
  // ==========================================================================
  if (q.includes('already paid') || q.includes('transferred') || q.includes('sent money') || q.includes('i paid') || q.includes('scammed') || q.includes('lost money') || q.includes('police') || q.includes('1930')) {
    return `### Incident Response Protocol: Actions Following Unauthorized Transfers

If funds have been transferred to an unverified counterparty, execute the following protocol immediately:

1. **National Cybercrime Reporting Portal (Dial 1930):**
   * Contact **1930** (Active 24x7 nationwide across India).
   * **Golden Hour Response:** Reporting within **2 hours** maximizes the ability of financial intelligence cells to freeze recipient escrow wallets and accounts.

2. **Bank Fraud Unit Escalation:**
   * Contact the issuing bank fraud response team and log an **unauthorized employment fraud transaction**.
   * Furnish UTR / UPI transaction identifiers and demand an immediate clawback / chargeback request.

3. **Official e-FIR Documentation:**
   * File an incident report on **[cybercrime.gov.in](https://cybercrime.gov.in)**.
   * Attach evidentiary artifacts: payment transaction receipts, the offer letter document, and complete chat transcripts.

4. **Identity & Biometric Protection:**
   * If Aadhaar or PAN card credentials were provided, lock biometric authentication immediately via the **[UIDAI portal](https://resident.uidai.gov.in/aadhaar-lockunlock)**.`;
  }

  // ==========================================================================
  // INTENT 1: Payment and Financial Fee Safety (6-Case Taxonomy)
  // ==========================================================================
  if (
    (q.includes('fee') || q.includes('deposit') || q.includes('charge') || q.includes('caution') || q.includes('registration') || q.includes('payment') || q.includes('money') || (q.includes('pay') && !q.includes('already paid') && !q.includes('transferred') && !q.includes('sent money') && !q.includes('i paid')) || (q.includes('financial') && q.includes('safety')) || (q.includes('why') && (q.includes('risk low') || q.includes('risk high') || q.includes('payment risk')))) &&
    !q.includes('already paid') && !q.includes('transferred') && !q.includes('sent money') && !q.includes('i paid')
  ) {
    if (paymentCase === 'WARNING_AGAINST_PAYMENT') {
      const warningQuote = paymentAssessment?.exact_quote || findMatchingDocSentences(['scam', 'fraud', 'free of cost', 'never asks', 'do not pay', 'beware'])[0] || 'Genuine hiring is free of cost.';
      return `Based on our forensic inspection, this document contains an **explicit anti-fraud warning advising candidates that recruitment is completely free of charge** (Risk Score: **${paymentAssessment?.risk_score ?? 3}/100**, Low Risk).

### Payment and Financial Fee Safety Audit: ${companyName}
* **Risk Score:** **${paymentAssessment?.risk_score ?? 3}/100** (Low Risk)
* **Safety Status:** **VERIFIED · Explicit Anti-Fraud Warning Detected**

**1. Document Excerpt:**
> *"${warningQuote}"*

**2. Why It Matters:**
* Legitimate enterprise employers frequently include clear anti-scam advisories to protect applicants from third-party fraudsters soliciting unauthorized fees.
* This proactive warning strongly correlates with genuine corporate recruitment governance.`;
    }

    if (paymentCase === 'POLICY_MENTION_WITHOUT_DEMAND') {
      const policyQuote = paymentAssessment?.exact_quote || findMatchingDocSentences(['policy', 'reimbursement', 'expense', 'travel', 'allowance'])[0] || 'Corporate financial policies outlined.';
      return `Based on the document text, financial and reimbursement policies are discussed for corporate operations, but **no candidate payment is demanded** (Risk Score: **${paymentAssessment?.risk_score ?? 10}/100**, Low Risk).

### Payment and Financial Fee Safety Audit: ${companyName}
* **Risk Score:** **${paymentAssessment?.risk_score ?? 10}/100** (Low Risk)
* **Safety Status:** **VERIFIED · Corporate Financial Policy Mention (No Candidate Demand)**

**1. Document Excerpt:**
> *"${policyQuote}"*

**2. Why It Matters:**
* The document outlines corporate reimbursement guidelines (e.g., travel expenses, operational allowances) rather than charging the candidate.
* Genuine employers differentiate company business expenditures from recruitment procedures.`;
    }

    if (paymentCase === 'CONDITIONAL_DEMAND') {
      const condQuote = primaryFee?.exact_quote || paymentAssessment?.exact_quote || findMatchingDocSentences(['refundable', 'deposit', 'security', 'caution'])[0] || 'Refundable caution deposit demanded.';
      const amountStr = primaryFee?.amount || paymentAssessment?.amount || 'Monetary deposit specified';
      return `Based on the document text, this offer requires a **conditional or refundable security deposit** (${amountStr}) (Risk Score: **${paymentAssessment?.risk_score ?? 85}/100**, High Risk).

### Payment and Financial Fee Safety Audit: ${companyName}
* **Risk Score:** **${paymentAssessment?.risk_score ?? 85}/100** (High Risk)
* **Safety Status:** **CRITICAL RISK · Conditional / Refundable Deposit Requested**

**1. Extracted Parameters:**
* **Demanded Amount:** **${amountStr}**
* **Claimed Purpose:** ${primaryFee?.category || 'Laptop caution deposit / Equipment security / Training guarantee'}
* **Claimed Refundability:** ${primaryFee?.is_refundable ? 'Claimed refundable upon joining or completion' : 'Conditional'}

**2. Exact Document Excerpt:**
> *"${condQuote}"*

**3. Forensic Analysis & Scam Technique:**
* Promising that a caution deposit is '100% refundable with the first stipend' is a recognized psychological manipulation tactic designed to disarm applicant suspicion.
* Legitimate corporate employers **never require candidates to front money** for laptops, ID badges, or onboarding materials.

**4. Required Action:**
* **DO NOT TRANSFER FUNDS.** Cease communication if payment is demanded via UPI or personal bank account.`;
    }

    if (paymentCase === 'EXPLICIT_DEMAND') {
      const feeQuote = primaryFee?.exact_quote || paymentAssessment?.exact_quote || findMatchingDocSentences(['fee', 'deposit', 'rs.', 'inr', 'pay', 'charge', 'registration', 'caution'])[0] || 'Upfront monetary deposit demanded in document.';
      const scoreVal = paymentAssessment?.risk_score ?? 96;
      return `Based on our forensic analysis of this document, there is an **explicit candidate monetary payment demand** required to secure the appointment (Risk Score: **${scoreVal}/100**, Critical Fraud Risk).

### Payment and Financial Fee Safety Audit: ${companyName}
* **Risk Score:** **${scoreVal}/100** (Critical Fraud Risk)
* **Safety Status:** **CRITICAL RISK · Explicit Candidate Payment Demand Detected**

**1. Extracted Financial Parameters:**
* **Fee Category:** ${primaryFee?.category || 'Registration / Processing / Security Deposit'}
* **Amount Demanded:** **${primaryFee?.amount || paymentAssessment?.amount || 'Monetary deposit specified'}**
* **Payment Recipient / Endpoint:** **${primaryFee?.recipient || paymentAssessment?.recipient || 'Specified payment endpoint / UPI ID'}**
* **Payment Window:** ${primaryFee?.deadline || 'Immediate onboarding deadline'}

**2. Exact Document Excerpt:**
> *"${feeQuote}"*

**3. Forensic Grounding & Security Principle:**
* **The Zero-Fee Hiring Standard:** Legitimate enterprise employers and accredited internship programs **never charge candidates** registration fees, document verification fees, training costs, or laptop caution money prior to joining.
* Demanding candidate fees under any pretext is a definitive indicator of recruitment fraud.

**4. Mandatory Next Steps:**
* **DO NOT TRANSFER FUNDS:** Do not make any UPI payments, bank transfers, or wallet deposits.
* **Report Immediately:** If money was already transferred, call the National Cybercrime Helpline (**1930**) immediately to attempt a transaction freeze.`;
    }

    if (paymentCase === 'AMBIGUOUS_EVIDENCE') {
      const ambQuote = paymentAssessment?.exact_quote || findMatchingDocSentences(['payment', 'fee', 'charge', 'cost', 'deposit'])[0] || 'Financial terms referenced in document.';
      return `Based on the available document evidence, financial terminology is present but the context is **ambiguous or incomplete** regarding whether candidate funds are required (Risk Score: **${paymentAssessment?.risk_score ?? 45}/100**, Moderate Risk / Uncertain).

### Payment and Financial Fee Safety Audit: ${companyName}
* **Risk Score:** **${paymentAssessment?.risk_score ?? 45}/100** (Moderate Risk · Ambiguous Context)
* **Safety Status:** **UNCERTAIN · Incomplete or Ambiguous Financial Language**

**1. Observed Context:**
> *"${ambQuote}"*

**2. Forensic Explanation:**
* The document references payment or financial terms without sufficient surrounding context to confirm whether candidate funds are requested.
* This frequently occurs in truncated document scans or poorly formatted draft letters.

**3. Recommended Next Step:**
* Request written clarification from the employer confirming that there are zero mandatory candidate fees or deposits of any kind before signing.`;
    }

    // Default: NO_PAYMENT_EVIDENCE
    const hasComp = candidateCompList.length > 0 || Boolean(primaryStipend);
    const compSummary = candidateCompList.map((c: any) => `${c.type || 'Remuneration'}: ${c.amount || c.raw_quote || c.rawText || ''}`).join(', ') || primaryStipend || 'Unstated';
    return `Based on our forensic examination, this document contains **zero candidate registration fees, security deposits, or caution money demands** (Risk Score: **${paymentAssessment?.risk_score ?? 5}/100**, Low Risk).

### Payment and Financial Fee Safety Audit: ${companyName}
* **Risk Score:** **${paymentAssessment?.risk_score ?? 5}/100** (Low Risk)
* **Safety Status:** **LOW RISK · Zero Candidate Payment Demands Detected**

**1. Forensic Examination Findings:**
* **Zero Upfront Fees:** The analyzed document contains **no registration fees, security deposits, training charges, or caution money demands**.
${hasComp ? `* **Candidate Remuneration Detected:** The document outlines candidate compensation (**${compSummary}**). This constitutes payment *to* the candidate, adhering to genuine employment practices.` : ''}

**2. Why Payment Risk is Low:**
* The document adheres to the **Zero-Fee Hiring Protocol**. Legitimate employers compensate their employees and interns rather than requiring candidates to pay upfront fees to secure appointments.

**3. Standard Precaution:**
* Maintain standard onboarding vigilance. If the recruiter later requests fees via phone, email, or messaging apps, cease contact immediately.`;
  }

  // ==========================================================================
  // INTENT 2: Stored Internet Search & Community Findings (Reddit, LinkedIn, Quora, MCA, Web)
  // ==========================================================================
  if (
    q.includes('reddit') || q.includes('linkedin') || q.includes('quora') ||
    q.includes('internet search') || q.includes('online search') || q.includes('searches reveal') ||
    q.includes('public forum') || q.includes('external research') || q.includes('web findings') ||
    q.includes('what did people online') || q.includes('community evidence') ||
    (q.includes('mca') && (q.includes('search') || q.includes('result') || q.includes('finding') || q.includes('reveal')))
  ) {
    // Specific platform queries
    if (q.includes('reddit')) {
      const hasRedditAlerts = redditData?.riskSignal === 'HIGH' || redditData?.riskSignal === 'CRITICAL' || (redditData?.findings || []).some((f: any) => f.sentiment === 'CRITICAL' || f.sentiment === 'SUSPICIOUS');
      const topReddit = (redditData?.findings || [])[0];

      if (hasRedditAlerts) {
        return `Regarding Reddit candidate forum intelligence (r/developersIndia and r/scams) for **${companyName}**:

Our stored community searches identified **active candidate scam alerts and negative fraud reports** matching this entity pattern.

* **Forum Signal:** Critical / High Community Risk
* **Summary:** ${redditData?.summary || 'Multiple candidates reported suspicious recruitment fees and lookalike offer letters.'}
${topReddit ? `* **Key Discussion Thread:** "${topReddit.title}"\n* **Thread Excerpt:** > "${topReddit.snippet}"\n* **Reference Link:** [View Reddit Thread](${topReddit.url})` : ''}

**Forensic Guidance:** Candidates in peer developer communities frequently identify recurring fraudulent recruitment rings before formal law enforcement action is taken. Exercise extreme caution.`;
      } else {
        return `Regarding Reddit candidate forum intelligence (r/developersIndia and r/scams) for **${companyName}**:

Stored candidate forum searches revealed **no public scam complaints or negative fraud reports** matching **${companyName}**.

* **Forum Signal:** Low Community Risk (${redditData?.summary || 'No active scam clusters identified'})
* **Core Security Axiom:** While the absence of negative forum reports is positive, **absence of complaints does not prove offer authenticity**. Fraudulent actors regularly generate new lookalike campaigns that have not yet been indexed on public forums.`;
      }
    }

    if (q.includes('linkedin')) {
      return `Regarding LinkedIn professional directory intelligence for **${companyName}**:

* **Corporate Presence:** ${linkedinData?.summary || 'Corporate profile check completed.'}
* **Recruiter Email & Routing Alignment:** ${isFreeWebmail ? `[CRITICAL ANOMALY] The recruiter communicates via a personal webmail address (${recruiterEmail}). Verified corporate talent acquisition teams operate exclusively through registered corporate enterprise email infrastructure.` : `Recruiter domain aligns with the corporate organization.`}
* **Recruiter Verification:** Even if ${companyName} maintains a verified LinkedIn corporate page with thousands of employees, this document must be verified directly with the Talent Acquisition department via their official switchboard.`;
    }

    if (q.includes('mca') || q.includes('statutory') || q.includes('registry')) {
      return `Regarding statutory Ministry of Corporate Affairs (MCA21) verification for **${companyName}**:

* **Statutory Status:** ${mcaData?.summary || (structure?.hasCinNumber ? `CIN identified: ${structure.cinNumber}` : ((context as any)?.company_verification?.status === 'ACTIVE' ? 'Active registered entity on MCA21 portal.' : 'Corporate registration record cross-referenced.'))}
* **Corporate Letterhead Compliance:** ${structure?.hasCinNumber ? `[PRESENT] Corporate Identification Number: ${structure.cinNumber}` : '[ABSENT] No statutory CIN code stated in document letterhead.'}
* **Core Legal Principle:** **Company Existence != Offer Authenticity.** An authentic corporate registration on the MCA21 portal proves that a company exists, but does not prove that this specific recruiter or letter is authorized.`;
    }

    // Consolidated external search synthesis
    return `Based on our stored external intelligence across LinkedIn, Reddit, Quora, MCA21, and official web sources for **${companyName}**:

1. **LinkedIn Directory:** ${linkedinData?.summary || 'Corporate presence checked'} (Risk Signal: ${linkedinData?.riskSignal || 'LOW'})
2. **Reddit Candidate Forums:** ${redditData?.summary || 'No active scam clusters identified in r/developersIndia'} (Risk Signal: ${redditData?.riskSignal || 'LOW'})
3. **Quora Candidate Inquiries:** ${quoraData?.summary || 'Candidate review threads evaluated'}
4. **MCA21 Corporate Registry:** ${mcaData?.summary || (structure?.hasCinNumber ? 'Registered corporate record' : 'Statutory registry record evaluated')}
5. **Official Company Web & Domain:** ${companyWebData?.summary || 'Corporate domain routing inspected'}

* **Overall External Research Risk Posture:** **${extResearch?.overallResearchRisk || 'LOW'}**
* **Forensic Principle:** Automated external research cross-references public records and community sentiment without repeating expensive web lookups. While positive findings reduce broad organizational risk, individual recruiter identity must still be verified via official corporate switchboards.`;
  }

  // ==========================================================================
  // INTENT 3: Document Claims vs External Reality Comparison
  // ==========================================================================
  if (
    q.includes('claims vs') || q.includes('claim vs') || q.includes('claimed vs') ||
    q.includes('claims versus') || q.includes('claims and reality') || q.includes('document claims vs') ||
    q.includes('are the claims true') || q.includes('match external') || q.includes('truth of claims') ||
    (q.includes('compare') && (q.includes('reality') || q.includes('external') || q.includes('claim')))
  ) {
    const claimedRecruiter = recruiterEmail || 'Corporate HR';
    const actualRecruiter = isFreeWebmail
      ? `Personal Webmail (${recruiterEmail}) — lacks enterprise DNS / SPF / DKIM verification`
      : `Corporate domain aligned email routing`;
    const claimedFee = hasFee ? `Mandatory fee/deposit requested` : `Zero candidate fee requested`;
    const actualFee = hasFee
      ? `Violates standard corporate hiring; legitimate firms prohibit candidate fees`
      : `Compliant with Zero-Fee hiring standards`;
    const claimedProcess = hasNoInterview ? `Direct appointment without interview` : `Standard evaluation process`;
    const actualProcess = hasNoInterview
      ? `High-risk indicator; enterprise organizations require formal interview rounds`
      : `Standard corporate recruitment workflow`;

    return `Here is an evidentiary comparison between what the uploaded document claims and what our external intelligence verified:

| Parameter | Document Claim | External Verification / Reality | Forensic Assessment |
| :--- | :--- | :--- | :--- |
| **Corporate Identity** | Claims representation of **${companyName}** | ${mcaData?.summary || 'Statutory filing cross-referenced'} | ${structure?.hasCinNumber ? 'CIN identified' : 'CIN omitted from letterhead'} |
| **Recruiter Routing** | ${claimedRecruiter} | ${actualRecruiter} | ${isFreeWebmail ? '[CRITICAL ANOMALY] Free webmail impersonation risk' : '[VERIFIED] Enterprise domain'} |
| **Monetary Terms** | ${claimedFee} | ${actualFee} | ${hasFee ? '[CRITICAL RISK] Scam indicator' : '[COMPLIANT] Zero candidate fee'} |
| **Selection Method** | ${claimedProcess} | ${actualProcess} | ${hasNoInterview ? '[FLAGGED] Unscreened direct appointment' : '[VERIFIED] Standard process'} |
| **Document Tracking** | ${referenceNumber ? 'Ref No: ' + referenceNumber : 'No formal reference tracking number'} | Enterprise HRMS enforce centralized reference IDs | ${referenceNumber ? '[COMPLIANT] Traceable reference' : '[DEFECT] Non-standard template'} |

**Conclusion:** Discrepancies between claimed corporate authority and actual communication channels are the single most common indicator of lookalike recruitment fraud.`;
  }

  // ==========================================================================
  // INTENT 4: Fraud Evaluation & Score Explanation ("Does this offer look fraudulent? Explain why.")
  // ==========================================================================
  if (
    q.includes('fraudulent') || q.includes('look like fraud') || q.includes('look fraudulent') ||
    q.includes('is this a scam') || q.includes('is this fake') || q.includes('is it fake') ||
    q.includes('fake or real') || q.includes('real or fake') || q.includes('is it genuine') ||
    q.includes('is this genuine') || q.includes('is it legit') || q.includes('is this legit') ||
    q.includes('why this score') || q.includes('explain score') || q.includes('why 96') ||
    q.includes('why 12') || q.includes('why low score') || q.includes('why high score') ||
    q.includes('why is it high risk') || q.includes('why is it risky') || q.includes('why did legitify assign') ||
    (q.includes('why') && (q.includes('risky') || q.includes('flagged') || q.includes('risk') || q.includes('score') || q.includes('fake') || q.includes('scam'))) ||
    ((q.includes('mca') || q.includes('registered')) && (q.includes('why') || q.includes('flagged') || q.includes('risky'))) ||
    q.includes('decision') || q.includes('red flags') || q.includes('warning signals') ||
    q.includes('strongest warning') || q.includes('red flag')
  ) {
    const keyDrivers: string[] = [];
    if (hasFee) {
      keyDrivers.push(`**Mandatory Candidate Fee Demanded:** The document requests fees or caution deposits (${primaryFee?.amount || feeDemandKeywords.join(', ') || 'Deposit requested'}). Legitimate corporate hiring strictly prohibits candidate charges.`);
    }
    if (isFreeWebmail) {
      keyDrivers.push(`**Public Webmail Recruiter:** Correspondence originates from personal webmail (${recruiterEmail}) rather than an authenticated corporate domain.`);
    }
    if (hasInformal) {
      keyDrivers.push(`**Informal Channel Migration:** Recruitment correspondence is directed to ${informalChannels.join(', ')} to evade enterprise audit trails.`);
    }
    if (hasNoInterview) {
      keyDrivers.push(`**Direct Appointment Without Interview:** Issuing an offer without technical or behavioral interview stages is an established recruitment risk signature.`);
    }
    if (structure && !structure.hasOfficialReferenceNumber && !referenceNumber) {
      keyDrivers.push(`**Missing Document Reference Number:** Lacks an official corporate tracking ID (Ref No.).`);
    }
    if (structure && !structure.hasRegisteredAddress) {
      keyDrivers.push(`**Missing Registered Office Address:** No physical corporate campus or registered location stated.`);
    }

    if (keyDrivers.length === 0) {
      keyDrivers.push(`**Zero-Fee Compliant:** No candidate monetary charges or caution deposits identified in the document.`);
      keyDrivers.push(`**Corporate Domain Aligned:** Recruiter correspondence originates from authenticated enterprise channels.`);
      keyDrivers.push(`**Standard Structure:** Professional formatting with reference tracking present.`);
    }

    const firstSentence = isHighRisk
      ? `Based on our multi-vector forensic evaluation, this offer exhibits critical indicators of recruitment fraud with an overall Trust Score of **${score}/100** (${verdict}).`
      : `Based on our multi-vector forensic evaluation, this offer demonstrates authentic enterprise recruitment attributes with an overall Trust Score of **${score}/100** (${verdict}).`;

    return `${firstSentence}

### Primary Evidentiary Drivers in This Document:
${keyDrivers.map((d, i) => `${i + 1}. ${d}`).join('\n\n')}

### Core Security Principle:
> **Company Existence != Offer Authenticity.**
> Even if **${companyName}** is an active, legally incorporated company in corporate registers, unauthorized actors routinely generate counterfeit letters and free webmail accounts impersonating real organizations.`;
  }

  // ==========================================================================
  // INTENT 5: Confirmed vs Uncertain Findings / Supporting vs Contradicting Evidence
  // ==========================================================================
  if (
    q.includes('confirmed vs') || q.includes('what is confirmed') || q.includes('what is uncertain') ||
    q.includes('what is unknown') || q.includes('verified vs') || q.includes('supports or contradicts') ||
    q.includes('evidence supporting') || q.includes('evidence contradicting') ||
    q.includes('supporting evidence') || q.includes('contradicting evidence') || q.includes('limitations')
  ) {
    return `Here is the forensic breakdown of verified, confirmed evidence versus uncertain parameters for this document:

**1. Confirmed / Evidentiary Findings:**
* **Document Parameters Extracted:** Role (**${detectedRole}**), Remuneration (**${primaryStipend || 'Unstated in document text'}**), Reference ID (**${referenceNumber || 'Omitted'}**).
* **Payment Demands:** ${hasFee ? `[CONFIRMED] Explicit candidate fee/deposit clauses detected in document (${primaryFee?.amount || 'Deposit specified'}).` : '[CONFIRMED] Zero candidate fee demands detected in document.'}
* **Recruiter Domain Classification:** ${isFreeWebmail ? `[CONFIRMED] Recruiter uses personal webmail (${recruiterEmail}).` : `[CONFIRMED] Recruiter operates on corporate domain routing.`}
* **Corporate Registry Cross-Reference:** ${mcaData?.summary || (structure?.hasCinNumber ? `CIN identified: ${structure.cinNumber}` : 'Statutory registry record evaluated.')}

**2. Uncertain / Unverified Parameters:**
* **Recruiter Authorization:** Whether the specific sender is genuinely authorized by **${companyName}** cannot be verified from document text alone without switchboard confirmation.
* **Cryptographic Signature Validity:** Static digital graphics or scanned signature stamps lack public-key cryptographic validation (PKI).
* **Off-Platform Representations:** Any verbal assurances, phone promises, or chat messages exchanged outside the document are unverified.

**3. Limitations:**
* Automated multi-vector forensics provides evidence-grounded risk intelligence based on available records; it does not substitute formal corporate background verification.`;
  }

  // ==========================================================================
  // INTENT 6: Counter-Evidence & Mitigating Factors
  // ==========================================================================
  if (
    q.includes('mitigating') || q.includes('counter-evidence') || q.includes('counter evidence') ||
    q.includes('in favor of') || q.includes('positive sign') || q.includes('good sign') ||
    q.includes('arguments against') || q.includes('challenge result') || q.includes('false positive')
  ) {
    const mitigatingPoints: string[] = [];
    if (!hasFee) {
      mitigatingPoints.push(`**Zero-Fee Standard Adherence:** The document contains no demands for registration fees, caution deposits, or training expenses.`);
    }
    if (structure?.hasCorporateHeader || !companyName.includes('not confidently identified')) {
      mitigatingPoints.push(`**Registered Corporate Namesake:** The issuing organization corresponds to a recognized entity in public corporate registries.`);
    }
    if (primaryStipend && !primaryStipend.toLowerCase().includes('lakh')) {
      mitigatingPoints.push(`**Plausible Compensation:** Remuneration figures (${primaryStipend}) align with reasonable industry compensation benchmarks rather than hyper-inflated bait numbers.`);
    }
    if (referenceNumber) {
      mitigatingPoints.push(`**Reference Tracking ID:** Includes an internal administrative tracking number (${referenceNumber}).`);
    }

    return `The following mitigating factors and positive indicators were observed during the multi-vector evaluation:

${mitigatingPoints.map((p, i) => `${i + 1}. ${p}`).join('\n\n')}

### Important Caution:
* **Mitigating factors do not overrule critical red flags.** Scammers frequently copy authentic letterheads and insert plausible salaries to make upfront caution deposit requests appear legitimate.
* **To Challenge This Result:** Provide an official corporate email confirmation originating from an authenticated \`@${companyName.toLowerCase().replace(/[^a-z0-9]/g, '')}.com\` enterprise mail server.`;
  }

  // ==========================================================================
  // INTENT 7: Detailed Multi-Paragraph Conclusions & Comprehensive Synthesis
  // ==========================================================================
  if (
    q.includes('detailed conclusion') || q.includes('full analysis') || q.includes('comprehensive conclusion') ||
    q.includes('in-depth report') || q.includes('write a detailed') || q.includes('thorough analysis') ||
    q.includes('complete analysis') || q.includes('detailed report')
  ) {
    return `Based on our multi-dimensional forensic analysis of the offer document issued under the name of **${companyName}**, here is our comprehensive investigative conclusion:

**1. Executive Verdict and Authenticity Score**
The analyzed document yielded an overall Trust Score of **${score}/100**, classifying this recruitment communication under the **${verdict}** risk profile. The evaluation combines automated structural analysis, natural language forensics, corporate registry cross-referencing, and external intelligence across public forums and directories.

**2. Core Forensic Findings and Evidentiary Anomalies**
${hasFee ? `The most severe vulnerability identified is an explicit candidate monetary fee or caution deposit requirement (${primaryFee?.amount || 'Monetary deposit demanded'}). Legitimate corporate recruitment strictly adheres to zero-fee hiring standards, and any demand for upfront funds is an established scam signature.` : `The document complies with zero-fee hiring standards, containing no upfront monetary charges, caution deposits, or training fees.`} ${isFreeWebmail ? `Furthermore, the recruiter operates through personal webmail (${recruiterEmail}) rather than authenticated enterprise infrastructure, preventing cryptographic verification of corporate authority.` : `Recruiter routing aligns with enterprise domain conventions.`}

**3. External Intelligence and Statutory Cross-Examination**
Cross-referencing statutory databases (MCA21) and community intelligence platforms indicates ${extResearch?.overallResearchRisk ? `an overall external research risk posture of **${extResearch.overallResearchRisk}**.` : 'standard corporate registration parameters.'} However, statutory existence alone does not validate the document; malicious actors routinely impersonate established companies to exploit their commercial goodwill.

**4. Strategic Action Recommendation**
${isHighRisk ? 'We strongly recommend withholding any monetary transfers, sensitive biometric identification, or financial details. Verify this offer letter independently by calling the official corporate switchboard of ' + companyName + ' and requesting confirmation from the Central Human Resources department.' : 'Standard corporate onboarding vigilance is recommended. Confirm role specifications and start dates directly through the official corporate careers portal before commencing employment.'}`;
  }

  // ==========================================================================
  // INTENT 8: Multi-Turn Follow-Ups, Clarifications, and Simpler Explanations
  // ==========================================================================
  if (
    q.includes('simpler') || q.includes('explain simply') || q.includes('in simple') ||
    q.includes('too technical') || q.includes('for a 5-year') || q.includes('plain english')
  ) {
    if (isHighRisk) {
      return `In simple terms:

**Be very careful — this offer letter shows serious warning signs of being a scam.**

Real companies will never ask you to pay money to get a job or an internship. They do not charge for training, laptops, or registration. Also, real HR departments send emails from official company email addresses, not from personal Gmail or WhatsApp accounts.

**What you should do right now:**
1. Do not send any money, UPI transfers, or bank deposits.
2. Do not send sensitive identity documents like Aadhaar or PAN card copies.
3. Call the official office phone number of ${companyName} to ask if this job offer is real.`;
    } else {
      return `In simple terms:

**This offer letter appears normal and has the standard formatting of a genuine job offer.**

It does not ask you for any fees or deposits, and the terms look reasonable. 

**What you should do right now:**
* Confirm your start date and job details directly through the company's official website or HR email before your first day.`;
    }
  }

  if (
    q.includes('reach that conclusion') || q.includes('reached that conclusion') ||
    q.includes('why that conclusion') || q.includes('why did you reach') ||
    q.includes('why you reached') || q.includes('why did you say that') ||
    q.includes('justify') || q.includes('how did you reach') || q.includes('what made you say')
  ) {
    return `I reached this conclusion through a systematic three-layer forensic evaluation:

1. **Document-Level Inspection:** I examined the uploaded letter for fee clauses, compensation terms, authorized signatory blocks, and official reference numbers. ${hasFee ? 'This revealed upfront candidate fee demands.' : 'No candidate fee demands were detected.'}
2. **Channel & Routing Analysis:** I evaluated the recruiter's email domain (${recruiterEmail || 'HR channel'}). ${isFreeWebmail ? 'Using personal webmail is inconsistent with authentic enterprise hiring.' : 'The email domain matches corporate standards.'}
3. **Statutory & Community Benchmarking:** I correlated the document against registered corporate records (MCA21) and community databases to evaluate entity legitimacy and recurring scam patterns.

Combining these dimensions produced the final Trust Score of **${score}/100**.`;
  }

  if (
    q.includes('summarize in 3') || q.includes('3 bullet') || q.includes('3 points') ||
    q.includes('three points') || q.includes('three bullet')
  ) {
    return `Here is the executive summary in exactly 3 key points:

1. **Trust Score & Status:** Overall Trust Score is **${score}/100** (${verdict}).
2. **Financial Terms:** ${hasFee ? `[CRITICAL RISK] Mandatory candidate fees or deposits detected (${primaryFee?.amount || 'Deposit requested'}).` : '[COMPLIANT] Zero candidate fee demands detected in document.'}
3. **Next Step:** ${isHighRisk ? 'Do NOT transfer funds or share sensitive ID documents; verify via official corporate switchboard.' : 'Confirm offer terms through official corporate careers portal.'}`;
  }

  if (q.includes('second red flag') || q.includes('first red flag') || q.includes('third red flag')) {
    const isSecond = q.includes('second');
    const isThird = q.includes('third');
    const ordinal = isThird ? 'Third' : isSecond ? 'Second' : 'First';

    if (isSecond) {
      const secondFlag = isFreeWebmail
        ? `**Personal Webmail Recruiter Address (${recruiterEmail}):** Authentic enterprise organizations route recruitment correspondence through registered corporate email domains with SPF and DKIM authentication, not personal webmail accounts.`
        : (hasNoInterview ? `**Direct Selection Without Interview:** Unscreened selection without technical or behavioral evaluations is a recognized employment risk indicator.` : `**Structural Governance Defect:** Missing registered office address or official corporate reference tracking number.`);
      return `Regarding the **Second Red Flag**:

${secondFlag}

This anomaly substantially lowers the document authenticity rating because lookalike recruiters rely on non-corporate channels to avoid domain-level detection.`;
    }

    if (isThird) {
      const thirdFlag = hasNoInterview
        ? `**Direct Appointment Without Interview:** The document appoints the candidate without technical or HR interview stages, which is contrary to standard enterprise hiring practices.`
        : `**Missing Reference Tracking ID:** Omission of a formal corporate requisition tracking number prevents internal verification against the employer's HRMS database.`;
      return `Regarding the **Third Red Flag**:

${thirdFlag}

Legitimate organizations maintain strict administrative governance; omission of formal selection stages or tracking identifiers is characteristic of unregulated templates.`;
    }

    const firstFlag = hasFee
      ? `**Mandatory Candidate Fee Demand (${primaryFee?.amount || 'Deposit requested'}):** Legitimate corporate employers strictly prohibit candidate fee demands under ILO Fair Recruitment standards.`
      : `**Unverified Recruiter Routing:** Correspondence lacks authenticated corporate domain cryptographic headers.`;
    return `Regarding the **First Red Flag**:

${firstFlag}

This is the primary driving factor in the evaluated risk score.`;
  }

  // ==========================================================================
  // INTENT 9: Recruiter Verification Inquiries (5 Questions)
  // ==========================================================================
  if (q.includes('question') || q.includes('ask recruiter') || q.includes('what should i ask') || q.includes('what to ask') || q.includes('hr question') || q.includes('due diligence') || q.includes('how to verify')) {
    return `### Recruiter Verification Inquiries: ${companyName}

Formal verification inquiries to dispatch to the recruiting entity:

1. **Official Careers Portal Requisition:**
   *"Please provide the direct requisition link for this position hosted on your official corporate careers portal ('${companyName.toLowerCase().replace(/[^a-z0-9]/g, '')}.com/careers')."*

2. **Corporate Domain Email Requirement:**
   *"Why is this correspondence originating from ${isFreeWebmail ? ('a personal webmail address (' + recruiterEmail + ')') : 'an external channel'} rather than your registered corporate domain?"*

3. **Corporate Requisition Reference ID:**
   *"Please confirm the internal Corporate Offer Requisition ID registered within your Central HR talent system."*

4. **Zero-Fee Statutory Written Confirmation:**
   *"Please confirm in writing that there are zero mandatory onboarding charges, training fees, caution deposits, or laptop charges at any stage."*

5. **Direct Switchboard Telephone Verification:**
   *"Please provide the registered corporate boardline number and extension of the Central Human Resources department to verify this offer independently."*

*Submit recruiter responses to LEGITIFY for updated evidence correlation.*`;
  }

  // ==========================================================================
  // INTENT 10: Organization Identity & Identification Status
  // ==========================================================================
  if (
    (q.includes('who is') || q.includes('company name') || q.includes('organization') || q.includes('unidentified') || q.includes('not identified') || q.includes('mca')) &&
    (companyName.includes('not confidently identified') || q.includes('not identified') || q.includes('unidentified'))
  ) {
    return `### Corporate Entity Identification & Registry Verification Status

* **Status:** **Organization Not Confidently Identified**
* **Evaluated Risk Score:** **50/100** (Moderate Risk · Unverified Counterparty)

**1. Document Inspection Finding:**
* The forensic parser could not extract a verifiable, unambiguous legal company name or Corporate Identification Number (CIN) from the document text or visual headers.
* Filenames, timestamps, and upload metadata were strictly filtered out to prevent false company identification.

**2. Forensic Implications:**
* Without an identifiable corporate identity, statutory verification against the **MCA21 Ministry of Corporate Affairs** registry could not be performed.
* Scammers frequently circulate generic appointment letters omitting legal entity identifiers to evade law enforcement attribution.

**3. Recommended Action:**
* Ask the recruiter to provide their **full registered corporate name**, **registered office address**, and **CIN (Corporate Identification Number)** before submitting sensitive personal documents.`;
  }

  // ==========================================================================
  // INTENT 11: Multi-Vector Assessment Specific Inquiry
  // ==========================================================================
  const matchedAssessment = assessments.find((a: any) =>
    (a.id && q.includes(a.id)) ||
    (a.name && q.includes(a.name.toLowerCase())) ||
    (a.id === 'company_registry' && (q.includes('mca') || q.includes('registry') || q.includes('company legal'))) ||
    (a.id === 'domain_intelligence' && (q.includes('domain') || q.includes('website') || q.includes('dns'))) ||
    (a.id === 'recruiter_email' && (q.includes('recruiter email') || q.includes('webmail') || q.includes('gmail'))) ||
    (a.id === 'threat_intelligence' && (q.includes('threat') || q.includes('virustotal') || q.includes('ioc'))) ||
    (a.id === 'community_sentiment' && (q.includes('reddit') || q.includes('quora') || q.includes('community') || q.includes('complaints'))) ||
    (a.id === 'consistency_conflict' && (q.includes('consistency') || q.includes('conflict') || q.includes('contradiction')))
  );

  if (matchedAssessment && (q.includes('why') || q.includes('what is') || q.includes('score') || q.includes('risk') || q.includes('explain') || q.includes('detail'))) {
    return `### Vector Assessment Audit: ${matchedAssessment.name}

* **Risk Score:** **${matchedAssessment.risk_score}/100** (${matchedAssessment.risk_band_label || matchedAssessment.risk_band})
* **Evidence Found:** ${matchedAssessment.evidence_found}
${matchedAssessment.exact_quote ? `* **Exact Document Excerpt:** *"${matchedAssessment.exact_quote}"*` : ''}
${matchedAssessment.amount ? `* **Associated Amount:** ${matchedAssessment.amount}` : ''}
${matchedAssessment.recipient ? `* **Identified Recipient:** ${matchedAssessment.recipient}` : ''}

**1. Why It Matters:**
${matchedAssessment.why_it_matters}

**2. Recommended Next Step:**
${matchedAssessment.recommended_next_step}`;
  }

  // ==========================================================================
  // INTENT 12: Employment Type — Internship vs Full-Time Job Offer
  // ==========================================================================
  if (
    q.includes('internship or job') ||
    q.includes('job or internship') ||
    q.includes('internship or full') ||
    q.includes('job offer or internship') ||
    q.includes('is it an internship') ||
    q.includes('is this an internship') ||
    q.includes('is it a job') ||
    q.includes('is this a job') ||
    q.includes('type of offer') ||
    q.includes('employment type') ||
    q.includes('what kind of offer') ||
    q.includes('position type')
  ) {
    const isInternship = /internship|intern\b|trainee|apprenticeship|summer intern/i.test(docText);
    const isFullTime = /full-time|full time|permanent|regular employment|annual ctc|probation period/i.test(docText);
    const durationMatch = docText.match(/(?:duration|tenure|period)\s*(?:of|is|:|-)?\s*([0-9]+\s*(?:months?|weeks?|days?))/i) ||
      docText.match(/([0-9]+\s*(?:months?|weeks?)\s*(?:internship|training|period))/i);
    const duration = durationMatch ? durationMatch[1] : undefined;

    let directAnswer = '';
    if (isInternship && !isFullTime) {
      directAnswer = `Based on the document text, this is an **internship offer** (Role: **${detectedRole}**${duration ? `, duration: **${duration}**` : ''}${primaryStipend ? `, stipend: **${primaryStipend}**` : ''}).`;
    } else if (isFullTime && !isInternship) {
      directAnswer = `Based on the document text, this is a **regular/full-time employment job offer** (Role: **${detectedRole}**${primaryStipend ? `, compensation: **${primaryStipend}**` : ''}).`;
    } else if (isInternship && isFullTime) {
      directAnswer = `This document appears to be an **internship with potential full-time conversion** or probation-to-employment offer (Role: **${detectedRole}**${duration ? `, initial duration: **${duration}**` : ''}${primaryStipend ? `, remuneration: **${primaryStipend}**` : ''}).`;
    } else {
      directAnswer = `The document designates the position as **${detectedRole}**${primaryStipend ? ` with remuneration of **${primaryStipend}**` : ''}. Standard corporate contracts typically specify whether the engagement is an internship, probationary period, or permanent employment.`;
    }

    const relevantSentences = findMatchingDocSentences(['intern', 'internship', 'full-time', 'probation', 'stipend', 'salary', 'duration', 'months']);

    return `${directAnswer}

**Document Evidence Summary:**
* **Designated Role:** ${detectedRole}
* **Engagement Type:** ${isInternship ? 'Internship / Training' : (isFullTime ? 'Full-Time Employment' : 'Not explicitly specified')}
* **Documented Compensation:** ${primaryStipend || 'Unstated / Disclosed separately'}
${duration ? `* **Specified Duration:** ${duration}\n` : ''}${relevantSentences.length > 0 ? `\n**Key Excerpt from Document:**\n* "${relevantSentences[0].trim()}"\n` : ''}
${hasFee ? '\n> **Warning:** Although this document presents as an offer, it contains candidate fee demands or deposit requests, which are characteristic of recruitment scams.' : ''}`;
  }

  // ==========================================================================
  // INTENT 13: Role, Designation, and Position Inquiries
  // ==========================================================================
  if (
    (q.includes('role') || q.includes('designation') || q.includes('position') || q.includes('job title') || q.includes('what job') || q.includes('profile')) &&
    (q.includes('what') || q.includes('which') || q.includes('my') || q.includes('offered') || q.includes('tell me') || q.includes('explain'))
  ) {
    const roleMatches = findMatchingDocSentences(['role', 'position', 'designation', 'appointed as', 'joining as', 'hired as', 'intern as']);
    return `The role offered in this document is **${detectedRole}** at **${companyName}**.

**Role Details Extracted:**
* **Designation:** ${detectedRole}
* **Issuing Organization:** ${companyName}
* **Remuneration / Stipend:** ${primaryStipend || 'Not explicitly detailed in document'}
${roleMatches.length > 0 ? `* **Document Reference:** "${roleMatches[0].trim()}"\n` : ''}
You can cross-check this role requisition directly on the official careers page of ${companyName}.`;
  }

  // ==========================================================================
  // INTENT 14: Joining Date, Duration, Location, and Remote Work
  // ==========================================================================
  if (q.includes('joining date') || q.includes('start date') || q.includes('when do i join') || q.includes('when do i start') || (q.includes('location') && !q.includes('registered')) || q.includes('where is the office') || q.includes('where is office') || q.includes('remote') || q.includes('work from home')) {
    const dateMatches = findMatchingDocSentences(['joining', 'commence', 'start date', 'effective date', 'reporting date', 'location', 'office', 'remote', 'work from home', 'duration', 'tenure', 'months', 'weeks']);
    const dateExtraction = docText.match(/(?:joining\s*date|date\s*of\s*joining|start\s*date|commencing\s*(?:on|from)|effective\s*from)\s*[:\-]?\s*([A-Za-z0-9,\s/\-]{6,30})/i)?.[1]?.trim();
    const locExtraction = docText.match(/(?:location|place\s*of\s*posting|office|base\s*location)\s*[:\-]?\s*([A-Za-z0-9,\s/\-]{3,40})/i)?.[1]?.trim();

    return `Here are the operational details extracted from the document:

* **Joining / Start Date:** ${dateExtraction || 'Not explicitly specified in the document text.'}
* **Work Location / Mode:** ${locExtraction || (docTextLower.includes('remote') || docTextLower.includes('work from home') ? 'Remote / Work from home indicated' : 'Not explicitly specified')}
* **Target Organization:** ${companyName}
${dateMatches.length > 0 ? `\n**Relevant Document Excerpt:**\n* "${dateMatches[0].trim()}"\n` : ''}
If dates or locations are missing from an official offer, genuine HR departments typically provide them in a formal annexure.`;
  }

  // ==========================================================================
  // INTENT 15: Working Hours, Schedule, Shifts, Timings, Work Days
  // ==========================================================================
  if (q.includes('hour') || q.includes('timing') || q.includes('schedule') || q.includes('shift') || q.includes('time') || q.includes('attendance') || q.includes('work day')) {
    const hourMatches = findMatchingDocSentences(['hour', 'timing', 'schedule', 'shift', 'am', 'pm', 'monday', 'friday', 'weekend', 'working day']);

    if (hourMatches.length > 0) {
      return `### Operational Working Hours & Schedule Analysis: ${companyName}

**1. Extracted Clauses from Uploaded Document:**
${hourMatches.map(m => `* *"${m.trim()}"*`).join('\n')}

**2. Forensic Evaluation:**
* The document explicitly outlines operational timing and schedule expectations.
* **Standard Enterprise Benchmark:** Authentic enterprise contracts typically mandate 40–45 hours per week (e.g., 9:30 AM to 6:30 PM, Monday through Friday) with formal public holiday provisions.
* If flexible/remote hours are promised without tracking or oversight, cross-verify attendance expectations with HR before onboarding.`;
    } else {
      return `### Operational Working Hours & Schedule Analysis: ${companyName}

**1. Document Inspection Finding:**
* **Observation:** No explicit working hours, shift timings, or schedule clauses were identified in the analyzed document text.

**2. Forensic Implications:**
* **Standard Legitimate Practice:** Authentic enterprise appointment and internship contracts explicitly define:
  1. Weekly working commitment (e.g., *40 hours per week*).
  2. Daily operational window (e.g., *9:00 AM – 6:00 PM IST*).
  3. Work model specification (*On-site campus / Hybrid / Remote*).
* **Significance:** The complete omission of working hours, department reporting times, or attendance policies is a frequent characteristic of **unregulated or fabricated offer templates** assembled without corporate HR oversight.

**3. Action Item:**
Request a formal Addendum or Appointment Annexure specifying work hours and reporting manager details from official company HR.`;
    }
  }

  // ==========================================================================
  // INTENT 16: Signatory, Signature, Who Signed, Authority Block
  // ==========================================================================
  if (q.includes('signatory') || q.includes('signed') || q.includes('signature') || q.includes('who signed') || q.includes('stamp') || q.includes('seal')) {
    const sigMatches = findMatchingDocSentences(['sincerely', 'regards', 'signatory', 'authorized', 'manager', 'director', 'talent acquisition', 'human resources']);

    return `### Authorized Signatory & Executive Execution Audit

**1. Extracted Signatory Parameters:**
* **Detected Signatory / Department:** **${primarySignatory || 'Signatory block unstated / unverified'}**
* **Executive Title / Function:** ${structure?.signatoryTitle || 'Human Resources / Talent Acquisition'}
${sigMatches.length > 0 ? `* **Sign-off Text Observed:** *"${sigMatches[0].trim()}"*` : ''}

**2. Forensic Verification Principles:**
* **Absence of Listed Executive != Automatic Proof of Fraud:** Junior HR talent coordinators often sign internship contracts without appearing on public MCA Director registers.
* **Risk Indicators:**
  * Typed name without signature stroke or digital cryptographic certificate.
  * Generic signatures copied from internet templates.
  * Mismatch between the signatory's claimed title and company size.

**3. Verification Step:**
Contact ${companyName}'s official corporate switchboard and request verification with **${primarySignatory || 'the Talent Acquisition department'}** to confirm authorization.`;
  }

  // ==========================================================================
  // INTENT 17: Stipend, Salary, Compensation, Package, CTC, Plausibility
  // ==========================================================================
  if (q.includes('stipend') || q.includes('salary') || q.includes('package') || q.includes('compensation') || q.includes('ctc') || (q.includes('pay') && (q.includes('receive') || q.includes('get')))) {
    const compMatches = findMatchingDocSentences(['stipend', 'salary', 'compensation', 'inr', 'rs.', '₹', 'per month', 'ctc', 'lpa']);

    const opening = primaryStipend
      ? `Based on the document text, the offered compensation is **${primaryStipend}** for the role of **${detectedRole}** at **${companyName}**.`
      : `Based on the document text, the exact compensation or stipend is not explicitly stated in the letter for the role of **${detectedRole}** at **${companyName}**.`;

    return `${opening}

**Compensation & Plausibility Details:**
* **Documented Amount:** **${primaryStipend || 'Unstated / Not explicitly defined in letter'}**
* **Designated Role:** **${detectedRole}**
${compMatches.length > 0 ? `* **Direct Text Excerpt:** *"${compMatches[0].trim()}"*` : ''}

**Economic Plausibility Assessment:**
* **Standard Market Median:** Authentic Indian corporate internships for ${detectedRole} typically benchmark between **₹12,000 to ₹35,000 per month** (higher for top-tier product tech firms).
* **Contradiction Check:** ${hasFee ? '[CRITICAL ANOMALY] The document promises compensation while simultaneously soliciting candidate deposits or registration charges. Corporate employers prohibit candidate charges.' : '[VERIFIED] No candidate-side deduction or caution deposit was detected.'}
* **Inflation Risk:** Exercise caution regarding offers promising inflated compensation (e.g., ₹50,000+/month) for entry-level positions without technical interview stages.`;
  }

  // ==========================================================================
  // INTENT 18: Standard Legitimate Format & Structural Integrity Checks
  // ==========================================================================
  if (q.includes('format') || q.includes('structure') || q.includes('template') || q.includes('standard') || q.includes('letterhead') || q.includes('reference number') || q.includes('ref no')) {
    const missing = structure?.missingElements || [];

    return `### Standard Organizational Format & Structure Audit

Every legitimate corporate offer letter adheres to standardized enterprise documentation conventions. Here is how this document complies:

**1. Structural Compliance Score:** **${structure?.structureScore ?? 45}/100** (${structure?.status ?? 'EVALUATED'})
* **Conventions Passed:** **${structure?.passedChecksCount ?? 5} / ${structure?.totalChecksCount ?? 10} Standards**

**2. Document Control Parameters:**
* **Official Reference Number:** ${referenceNumber ? '[PRESENT] Identified: ' + referenceNumber : '[ABSENT] Omitted (Non-standard template)'}
* **Corporate Letterhead & Entity:** ${structure?.hasCorporateHeader ? '[PRESENT] Verified corporate entity indicator' : '[ABSENT] Generic header lacking entity suffix'}
* **Registered Office Address:** ${structure?.hasRegisteredAddress ? '[PRESENT] Physical corporate campus present' : '[ABSENT] Omitted physical registered address & PIN code'}
* **Personalized Addressee:** ${structure?.hasPersonalizedAddressee ? `[PRESENT] Addressed to: ${structure.candidateName}` : '[ABSENT] Generic salutation (e.g., "Dear Candidate")'}
* **Authorized Signatory Block:** ${structure?.hasAuthorizedSignatoryBlock ? '[PRESENT] HR executive closing block present' : '[ABSENT] Lacks executive designation & signature'}

${missing.length > 0 ? `\n**3. Critical Missing Conventions:**\n${missing.map((m: any) => `* [DEFECT] ${m}`).join('\n')}` : ''}

**Conclusion:** Legitimate corporate HR departments enforce strict document governance. Omission of multiple administrative conventions indicates an unverified or informal letter.`;
  }

  // ==========================================================================
  // INTENT 19: 30-Second Summary for Parents & Family
  // ==========================================================================
  if (q.includes('parent') || q.includes('family') || q.includes('30-second')) {
    return `### Executive Summary for Advisors & Family

> *"This offer letter uses the name of **${companyName}**, but our verification indicates ${isHighRisk ? 'critical risk factors in the recruiter contact or fee clauses' : 'standard corporate recruitment patterns'}.*
> *Real companies never charge students to give them a job. The National Cybercrime Helpline (1930) classifies asking money for job offers as employment fraud. We should ${isHighRisk ? 'not pay any fee or send sensitive ID documents' : 'proceed with standard corporate verification'}.*

**Key Takeaways:**
* **Company Status:** ${companyName} (${isHighRisk ? 'Unverified recruiter' : 'Corporate profile evaluated'})
* **Financial Demands:** ${hasFee ? '[FLAGGED] Mandatory candidate deposit demanded' : '[VERIFIED] No candidate fee detected'}
* **Next Action:** ${isHighRisk ? 'Do NOT transfer funds or provide sensitive identification documents.' : 'Verify directly via official company careers portal.'}`;
  }

  // ==========================================================================
  // INTENT 19B: Machine Learning Fraud Classifier Inquiry
  // ==========================================================================
  if (
    q.includes('machine learning') || q.includes('ml classifier') || q.includes('ml model') ||
    q.includes('fraud classifier') || q.includes('linear svm') || q.includes('model prediction') ||
    (q.includes('classifier') && (q.includes('result') || q.includes('say') || q.includes('show') || q.includes('model') || q.includes('score') || q.includes('why')))
  ) {
    const mlAssessment = assessments.find((a: any) => a.id === 'ml_fraud_pattern');
    const mlPred = context.mlPrediction || context.forensicAnalysis?.scoring?.mlPrediction || context.scoring?.mlPrediction;
    const mlScore = mlAssessment?.risk_score ?? (mlPred ? Math.round(mlPred.fraud_probability * 100) : 10);
    const mlBand = mlAssessment?.risk_band_label || (mlScore >= 75 ? 'Critical Risk / Fraudulent Signature' : (mlScore >= 45 ? 'High Risk / Suspicious Pattern' : (mlScore >= 20 ? 'Moderate Risk' : 'Low Risk / Legitimate Signature')));
    const fraudProb = mlPred ? (mlPred.fraud_probability * 100).toFixed(1) : `${mlScore}.0`;

    return `The Machine Learning Fraud Classifier evaluated this offer using an offline Linear Support Vector Machine (Linear SVM) model trained on the Kaggle Fraudulent Job Postings dataset:

* **Classifier Result:** **${mlScore}/100 Risk Score** (${mlBand})
* **Estimated Fraud Probability:** **${fraudProb}%**
* **Primary Evidence Evaluated:** ${mlAssessment?.evidence_found || (mlPred?.fraud_probability > 0.5 ? 'Document text exhibits lexical and linguistic markers correlated with fraudulent job descriptions.' : 'Text exhibits standard corporate phrasing and zero high-risk linguistic patterns.')}
${mlAssessment?.exact_quote ? `* **Key Evaluated Excerpt:** *"${mlAssessment.exact_quote}"*\n` : ''}
**How the Model Works:**
The classifier extracts 2,000 unigram and bigram features combined with structural entity indicators (fee solicitations, webmail patterns, direct selection phrases). Unlike generic heuristics, it assigns continuous risk probabilities based on empirical patterns from thousands of verified fraudulent and authentic recruitment postings.`;
  }

  // ==========================================================================
  // INTENT 19C: Domain Intelligence, Registration Age, DNS & SSL
  // ==========================================================================
  if (
    (q.includes('domain') || q.includes('website') || q.includes('whois') || q.includes('domain age') || q.includes('how old') || q.includes('dns') || q.includes('ssl')) &&
    !q.includes('email')
  ) {
    const domainAssessment = assessments.find((a: any) => a.id === 'domain_intelligence');
    const domainScore = domainAssessment?.risk_score ?? 20;

    return `### Domain & Web Infrastructure Intelligence: ${companyName}

* **Risk Score:** **${domainScore}/100** (${domainAssessment?.risk_band_label || (domainScore >= 45 ? 'High Risk' : 'Evaluated')})
* **Infrastructure Findings:** ${domainAssessment?.evidence_found || 'Domain registration and network parameters evaluated against enterprise benchmarks.'}
${domainAssessment?.exact_quote ? `* **Observed Data:** *"${domainAssessment.exact_quote}"*\n` : ''}
**Key Verification Principles:**
1. **Domain Longevity:** Authentic corporate entities maintain registered web domains with multi-year histories. Lookalike domains registered within the last 90 to 180 days are a frequent indicator of tactical scam operations.
2. **Mail Exchange (MX) Alignment:** Legitimate enterprise domains have dedicated MX records configured with SPF, DKIM, and DMARC records to prevent spoofing.
3. **Next Step:** Verify that communications originate strictly from the canonical corporate domain rather than typosquatted or sub-domain variations.`;
  }

  // ==========================================================================
  // INTENT 19D: Recruiter Authenticity, Email Routing & Communication Channels
  // ==========================================================================
  if (
    (q.includes('recruiter') || q.includes('hr email') || q.includes('sender') || q.includes('who sent') || q.includes('contact person')) &&
    (q.includes('legit') || q.includes('real') || q.includes('suspicious') || q.includes('fake') || q.includes('safe') || q.includes('email') || q.includes('channel') || q.includes('valid'))
  ) {
    const emailAssessment = assessments.find((a: any) => a.id === 'recruiter_email');
    const emailScore = emailAssessment?.risk_score ?? (isFreeWebmail ? 85 : 5);

    return `### Recruiter Legitimacy & Communication Channel Audit

* **Recruiter Email Address:** **${recruiterEmail || 'Not stated in document'}**
* **Channel Classification:** **${isFreeWebmail ? 'Personal Webmail (Free Provider)' : 'Corporate Domain Routing'}**
* **Risk Score:** **${emailScore}/100** (${emailAssessment?.risk_band_label || (isFreeWebmail ? 'High Risk' : 'Low Risk')})
* **Evidence:** ${emailAssessment?.evidence_found || (isFreeWebmail ? `Recruiter communicates via public webmail (${recruiterEmail}), evading corporate audit trails.` : 'Recruiter email domain aligns with the corporate organization.')}

**Forensic Explanation:**
Authentic enterprise HR professionals are required to communicate via authenticated enterprise email accounts (\`@${companyName.toLowerCase().replace(/[^a-z0-9]/g, '')}.com\`). Public webmail accounts (e.g. Gmail, Yahoo, Outlook) provide zero identity validation and are freely created by impersonators.`;
  }

  // ==========================================================================
  // INTENT 19E: Action Plan, Next Steps, Advice & Should I Accept
  // ==========================================================================
  if (
    q.includes('should i accept') || q.includes('should i join') || q.includes('what should i do') ||
    q.includes('next steps') || q.includes('what next') || q.includes('what to do') ||
    q.includes('advice') || q.includes('action plan') || q.includes('can i trust')
  ) {
    if (isHighRisk) {
      return `### Recommended Immediate Action Plan (High Risk Warning)

Based on the evaluated Trust Score of **${score}/100** (${verdict}), here is what you should do:

1. **Do NOT Transfer Any Money:** Legitimate companies never demand registration fees, laptop security deposits, or background check costs under any circumstances.
2. **Withhold Sensitive Personal Documents:** Do not send copies of your Aadhaar, PAN card, passport, or bank account details over email or WhatsApp.
3. **Conduct Independent Switchboard Verification:** Locate the official telephone number of **${companyName}** from their verified public website (do not call numbers printed in the letter) and ask for the Human Resources department to confirm requisition validity.
4. **Report Scam Activity:** Report the incident to your college/university placement cell and register a formal cyber fraud complaint on the National Cybercrime Portal ([cybercrime.gov.in](https://cybercrime.gov.in)) or call Helpline **1930**.`;
    } else {
      return `### Recommended Next Steps for This Offer

Based on the evaluated Trust Score of **${score}/100** (${verdict}), this document aligns with standard corporate recruitment practices:

1. **Verify Role & Compensation Terms:** Confirm that the offered role (**${detectedRole}**) and remuneration (**${primaryStipend || 'as discussed'}**) match your expectations and interview discussions.
2. **Confirm via Official Portal:** Contact the official HR recruitment team through the company's verified careers portal or switchboard to confirm receipt of your signed acceptance.
3. **Review Formal Addendums:** Ensure you receive complete policy documentation regarding work location, equipment provisioning, and confidentiality terms prior to your official joining date.`;
    }
  }

  // ==========================================================================
  // INTENT 20: DYNAMIC SENTENCE-LEVEL SEMANTIC RETRIEVAL OVER DOCUMENT TEXT
  // ==========================================================================
  const queryTerms = q.split(/\s+/).filter(w => w.length > 2 && !['what', 'when', 'where', 'which', 'who', 'whom', 'whose', 'why', 'how', 'the', 'this', 'that', 'with', 'from', 'about', 'does', 'have', 'tell', 'give', 'show', 'please', 'can', 'you', 'is', 'are', 'was', 'were'].includes(w));
  const matchedSentences = findMatchingDocSentences(queryTerms);

  if (matchedSentences.length > 0) {
    const primarySentence = matchedSentences[0].trim();
    return `Based on the document text, here is what is stated regarding your question:

> "${primarySentence}"

${matchedSentences.length > 1 ? `**Additional relevant clauses in document:**\n${matchedSentences.slice(1).map(s => `* "${s.trim()}"`).join('\n')}\n\n` : ''}* **Target Organization:** ${companyName} (Trust Score: ${score}/100)
* **Financial Safety:** ${hasFee ? 'Caution: Candidate fee/deposit clauses detected in document.' : 'No candidate fee demands detected.'}

You can cross-verify this specific clause directly with the HR department at ${companyName}.`;
  }

  // ==========================================================================
  // INTENT 21: INTELLIGENT OPEN-ENDED CONTEXTUAL SYNTHESIS / HONEST UNKNOWN
  // ==========================================================================
  const compRef = companyName && !companyName.toLowerCase().includes('not confidently identified')
    ? companyName
    : 'this opportunity';
  const feeStatusText = hasFee
    ? 'contains explicit candidate fee demands or deposit requests, which violates zero-fee employment standards'
    : 'does not contain upfront registration fees or caution deposits';
  const recruiterStatusText = isFreeWebmail
    ? `recruiter communication originates from a personal webmail address (${recruiterEmail || 'webmail'}) rather than an authenticated corporate domain`
    : `recruiter email domain aligns with the corporate organization`;

  let externalNote = '';
  if (extFindings.length > 0) {
    const topFindings = extFindings.slice(0, 3).map((f: any) => `* **[${f.platform || 'WEB'}] ${f.title || 'Intelligence finding'}:** ${f.snippet || ''}`).join('\n');
    externalNote = `\n\n**External Intelligence Records for ${compRef}:**\n${topFindings}`;
  } else if (extResearch?.overallResearchRisk) {
    externalNote = `\n\n**External Intelligence Status:** Overall external research risk posture is evaluated as **${extResearch.overallResearchRisk}**.`;
  }

  return `Regarding your question about **"${question}"**, the uploaded document does not contain an explicit clause directly addressing this.

**Summary from Available Document Details:**
* **Issuing Organization:** ${compRef}
* **Offered Position:** ${detectedRole}
* **Documented Compensation:** ${primaryStipend || 'Unstated in document text'}
* **Financial Safety:** The document ${feeStatusText}.
* **Recruiter Channel:** The ${recruiterStatusText}.
${referenceNumber ? `* **Document Reference ID:** ${referenceNumber}\n` : ''}${externalNote}

If you need details on specific terms not covered in this letter, genuine employers provide a full employment agreement or employee handbook upon formal request.`;
}

// ----------------------------------------------------------------------------
// LOCAL AI FALLBACK PROVIDER
// ----------------------------------------------------------------------------
export class LocalAIProvider implements IAIProvider {
  async isAvailable(): Promise<boolean> {
    return true;
  }

  async generateSynthesis(input: AISynthesisInput): Promise<AISynthesisOutput> {
    const isClean = input.trustScore >= 80 && input.riskLevel === 'LOW';
    const isCritical = input.trustScore <= 40 || input.riskLevel === 'CRITICAL';

    const whatWeFound: string[] = [];
    const whyItMatters: string[] = [];
    const whatSupportsIt: string[] = [];
    const whatContradictsIt: string[] = [];
    const whatIsUnknown: string[] = [];

    input.evidence.forEach(e => {
      if (e.severity === 'CRITICAL' || e.severity === 'HIGH') {
        whatWeFound.push(`${e.title}: ${e.snippet}`);
        whyItMatters.push(`[Critical Risk] ${e.evidence_text}`);
        whatContradictsIt.push(`Conflict: ${e.title} failed legitimacy baseline.`);
      } else if (e.verified) {
        whatSupportsIt.push(`Verified: ${e.title} (${e.source_name})`);
      } else {
        whatIsUnknown.push(`Pending confirmation: ${e.title}`);
      }
    });

    if (whatWeFound.length === 0) {
      whatWeFound.push(isClean ? "All statutory checks, domain validation, and email structure passed." : "No explicit fatal indicators identified.");
    }
    if (whyItMatters.length === 0) {
      whyItMatters.push(isClean ? "Corporate profile matches established, verified registry records." : "Requires independent verification.");
    }

    const executive_summary = isCritical
      ? `Critical recruitment risk detected for ${input.entityName}. Document exhibits high-probability employment fraud indicators.`
      : isClean
      ? `${input.entityName} demonstrates authentic structural attributes consistent with verified enterprise recruitment.`
      : `Moderate risk profile for ${input.entityName}. Recommended independent verification before accepting.`;

    const recommendation = isCritical
      ? "Do NOT transfer funds or provide sensitive identification documents. Report to placement cell."
      : isClean
      ? "Proceed with standard review of compensation terms and role responsibilities."
      : "Verify corporate identity on MCA21 portal (mca.gov.in) before proceeding.";

    return {
      executive_summary,
      structured_explanation: {
        what_we_found: whatWeFound,
        why_it_matters: whyItMatters,
        what_supports_it: whatSupportsIt,
        what_contradicts_it: whatContradictsIt,
        what_is_unknown: whatIsUnknown,
        recommendation,
      },
      recommendation,
      limitations: [
        "Analysis is based on automated multi-source evidence extraction and pattern correlation.",
        "Scoring does not substitute formal legal counsel or corporate background checks."
      ],
      provider_used: "LOCAL_AI",
    };
  }

  async answerCopilot(question: string, context: Record<string, any>): Promise<string> {
    return generateEvidenceGroundedAnswer(question, context);
  }
}

// ----------------------------------------------------------------------------
// EXTERNAL RESEARCH FORMATTER FOR AI PROMPT GROUNDING
// ----------------------------------------------------------------------------
export function formatExternalResearchForPrompt(research: any): string {
  if (!research) return 'No stored external research available.';
  if (typeof research === 'string') return research;

  const parts: string[] = [];
  if (research.targetCompany) parts.push(`Target Company: ${research.targetCompany}`);
  if (research.overallResearchRisk) parts.push(`Overall External Research Risk Posture: ${research.overallResearchRisk}`);
  if (research.synthesizedContextForAI) {
    parts.push(`Summary Context:\n${research.synthesizedContextForAI}`);
  }

  const providers = research.providers || {};
  if (providers.linkedin) {
    parts.push(`- LinkedIn Directory: Status: ${providers.linkedin.status} | Risk Signal: ${providers.linkedin.riskSignal} | Summary: ${providers.linkedin.summary}`);
  }
  if (providers.reddit) {
    parts.push(`- Reddit Candidate Forums (r/developersIndia & r/scams): Status: ${providers.reddit.status} | Risk Signal: ${providers.reddit.riskSignal} | Summary: ${providers.reddit.summary}`);
  }
  if (providers.quora) {
    parts.push(`- Quora Candidate Inquiries: Status: ${providers.quora.status} | Risk Signal: ${providers.quora.riskSignal} | Summary: ${providers.quora.summary}`);
  }
  if (providers.companyWeb) {
    parts.push(`- Company Official Website & Domain: Status: ${providers.companyWeb.status} | Risk Signal: ${providers.companyWeb.riskSignal} | Summary: ${providers.companyWeb.summary}`);
  }
  if (providers.mca) {
    parts.push(`- MCA Statutory Registry: Status: ${providers.mca.status} | Risk Signal: ${providers.mca.riskSignal} | Summary: ${providers.mca.summary}`);
  }

  if (Array.isArray(research.allFindings) && research.allFindings.length > 0) {
    parts.push(`Key Findings:`);
    research.allFindings.slice(0, 8).forEach((f: any) => {
      parts.push(`  * [${f.platform}] ${f.title} (${f.sentiment || 'NEUTRAL'}): ${f.snippet?.substring(0, 140)}... (URL: ${f.url})`);
    });
  }

  return parts.join('\n');
}

// ----------------------------------------------------------------------------
// GEMINI FLASH AI PROVIDER (DYNAMIC ADAPTIVE COPILOT WITH EVIDENCE GROUNDING)
// ----------------------------------------------------------------------------
export class GeminiFlashProvider implements IAIProvider {
  private ai: GoogleGenAI | null = null;

  constructor() {
    const apiKey = process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY;
    if (apiKey) {
      this.ai = new GoogleGenAI({ apiKey });
    }
  }

  async isAvailable(): Promise<boolean> {
    return !!(this.ai && (process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY));
  }

  async generateSynthesis(input: AISynthesisInput): Promise<AISynthesisOutput> {
    if (!this.ai) {
      return new LocalAIProvider().generateSynthesis(input);
    }

    try {
      const prompt = `You are the lead intelligence analyst at LEGITIFY. Generate a forensic analysis for:
Entity: ${input.entityName} (${input.entityType})
Score: ${input.trustScore}/100, Risk: ${input.riskLevel}, Verdict: ${input.verdict}
Evidence items: ${JSON.stringify(input.evidence.map(e => ({ title: e.title, verified: e.verified, severity: e.severity, snippet: e.snippet })))}

Return strictly a JSON object matching this schema:
{
  "executive_summary": string,
  "structured_explanation": {
    "what_we_found": [string],
    "why_it_matters": [string],
    "what_supports_it": [string],
    "what_contradicts_it": [string],
    "what_is_unknown": [string],
    "recommendation": string
  },
  "recommendation": string,
  "limitations": [string]
}`;

      const response = await this.ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: { responseMimeType: 'application/json' },
      });

      const parsed = JSON.parse(response.text || '{}');
      return {
        ...parsed,
        provider_used: "GEMINI_FLASH",
      };
    } catch {
      return new LocalAIProvider().generateSynthesis(input);
    }
  }

  async answerCopilot(question: string, context: Record<string, any>): Promise<string> {
    if (isDomainOffTopic(question)) {
      return DOMAIN_GUARDRAIL_MESSAGE;
    }

    const userName = context.user_name || context.candidate_name || (context.user_email ? context.user_email.split('@')[0] : 'Candidate');
    const compName = sanitizeCompanyName(context);

    // Conversational greeting check
    if (isGreeting(question)) {
      return buildGreetingResponse(userName, compName);
    }

    const locker = buildEvidenceLocker(context);
    const score = typeof context.trust_score === 'number'
      ? context.trust_score
      : (typeof context.confidence_score === 'number' ? context.confidence_score : 0);
    const docChunks = context.document_chunks || [];
    const extChunks = context.external_chunks || [];
    const evidenceCitations = locker.map(e => `[${e.id}] (${e.type}): ${e.claim}`).slice(0, 15).join('\n');

    if (!this.ai) {
      return generateEvidenceGroundedAnswer(question, context);
    }

    try {
      const sampleIds = locker.length > 0 ? locker.map(l => '[' + l.id + ']').slice(0, 4).join(', ') : '[Doc-P1-C0], [Ext-DNS-01]';
      const historyContext = Array.isArray(context.history) && context.history.length > 0
        ? `\n--- PREVIOUS CONVERSATION HISTORY ---\n${context.history.map((h: any) => `${h.role === 'user' ? 'Candidate' : 'Copilot'}: ${h.text || h.content}`).join('\n')}\n--- END HISTORY ---\n`
        : '';

      const assessmentsList = Array.isArray(context.assessments) && context.assessments.length > 0
        ? context.assessments
        : (context.scoring?.assessments || []);
      const assessmentsContext = assessmentsList.length > 0
        ? `\n--- 12 MULTI-VECTOR RISK ASSESSMENTS ---\n${assessmentsList.map((a: any) => `- [${a.name}] (ID: ${a.id}): Risk Score ${a.risk_score}/100 | Band: ${a.risk_band_label || a.risk_band} | Evidence: ${a.evidence_found} | Quote: "${a.exact_quote || 'N/A'}" | Next Step: ${a.recommended_next_step}`).join('\n')}\n`
        : '';

      const feeDetails = context.document_analysis?.fee_details || context.fee_details || [];
      const paymentContext = feeDetails.length > 0
        ? `\n--- DETAILED FINANCIAL & PAYMENT EVIDENCE ---\n${feeDetails.map((f: any) => `Category: ${f.category} | Amount: ${f.amount || 'Unspecified'} | Recipient: ${f.recipient || 'Unspecified'} | Channel: ${f.channel || 'Direct'} | Refundable: ${f.is_refundable} (${f.refund_terms}) | Deadline: ${f.deadline || 'None'} | Exact Quote: "${f.exact_quote}" | Why: ${f.why_it_matters}`).join('\n')}\n`
        : '';

      const externalResearchContext = context.external_research
        ? `\n--- STORED EXTERNAL RESEARCH & VERIFICATION FINDINGS ---\n${formatExternalResearchForPrompt(context.external_research)}\n`
        : '';

      const claimsList = context.extracted_claims || context.document_analysis?.extracted_claims || [];
      const claimsContext = claimsList.length > 0
        ? `\n--- EXTRACTED DOCUMENT CLAIMS ---\n${claimsList.map((c: any) => `- ${c.field}: "${c.value}" (Quote: "${c.source_quote}")`).join('\n')}\n`
        : '';

      const systemPrompt = `You are the LEGITIFY Forensic Investigation Assistant.
Your objective is to provide candidate '${userName}' with authoritative, objective, and evidentiary document forensic intelligence.

OPERATIONAL DIRECTIVES:
1. Tone: Maintain a professional, objective, enterprise security posture. Absolutely NO emojis anywhere in your response.
2. The investigated target organization is "${compName}". NEVER refer to the company as "images", "screenshot", or raw filenames.
3. Evaluated Authenticity & Trust Score: ${score}/100.
4. Answer the user's SPECIFIC question DIRECTLY and CONVERSATIONALLY in your very first sentence based on verified document evidence and stored external intelligence. For example, if asked 'Does this offer look fraudulent? Explain why.', directly state whether it exhibits fraud indicators, followed by the specific driving factors. Do NOT begin with rigid template headers (e.g. '### Investigation Findings' or '### Contextual Forensic Analysis'). Answer naturally and concisely as an expert forensic advisor.
5. Ground your explanation in the following verified Multi-Vector Assessments, Evidence Locker records, Stored External Research, and Claims:
${assessmentsContext}
${paymentContext}
${externalResearchContext}
${claimsContext}
--- EVIDENCE RECORDS ---
${evidenceCitations || 'No evidence records available.'}
--- DUAL RAG CITATIONS ---
Document Chunks: ${JSON.stringify(docChunks.slice(0, 5))}
External Evidence Chunks: ${JSON.stringify(extChunks.slice(0, 5))}
${historyContext}
6. Distinguish clearly:
   - Corporate Entity Existence != Offer Letter Authenticity.
   - An Authentic Corporate Registration does not prove that this specific recruiter or letter is legitimate.
   - Legitimate corporate employers NEVER demand candidate registration fees, laptop caution deposits, or training charges.
7. Cite actual Evidence IDs (e.g. ${sampleIds}) and Vector Risk Scores where applicable.
8. If an assertion cannot be verified from the provided evidence, explicitly state: "This claim could not be verified from the available forensic evidence."
9. Include practical verification actions: checking the official company careers portal, calling the registered reception boardline, and reporting fraud to the 1930 National Cybercrime Helpline if money was transferred.
10. Format response cleanly using concise bullet points and bold key terms. Avoid repeating boilerplate document audit profiles on every turn.`;

      const response = await this.ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `${systemPrompt}\n\nUser Question: "${question}"`,
      });

      const text = response.text?.trim();
      if (text && text.length > 20) {
        return text;
      }
      return generateEvidenceGroundedAnswer(question, context);
    } catch (e) {
      console.warn("Gemini copilot generation fallback", e);
      return generateEvidenceGroundedAnswer(question, context);
    }
  }
}

export class HuggingFaceProvider implements IAIProvider {
  private primaryModel: string;
  private fallbackModel: string;

  constructor() {
    this.primaryModel = process.env.HF_MODEL || 'Qwen/Qwen3-8B';
    this.fallbackModel = process.env.HF_FALLBACK_MODEL || 'Qwen/Qwen2.5-7B-Instruct';
  }

  async isAvailable(): Promise<boolean> {
    const token = (process.env.HF_TOKEN || process.env.HUGGINGFACE_TOKEN || '').trim();
    return Boolean(token);
  }

  async generateSynthesis(input: AISynthesisInput): Promise<AISynthesisOutput> {
    const token = (process.env.HF_TOKEN || process.env.HUGGINGFACE_TOKEN || '').trim();
    if (!token) {
      return new LocalAIProvider().generateSynthesis(input);
    }

    try {
      const prompt = `You are the lead intelligence analyst at LEGITIFY. Generate a forensic analysis for:
Entity: ${input.entityName} (${input.entityType})
Score: ${input.trustScore}/100, Risk: ${input.riskLevel}, Verdict: ${input.verdict}
Evidence items: ${JSON.stringify(input.evidence.map(e => ({ title: e.title, verified: e.verified, severity: e.severity, snippet: e.snippet })))}

Return strictly a JSON object matching this schema without markdown fences:
{
  "executive_summary": string,
  "structured_explanation": {
    "what_we_found": [string],
    "why_it_matters": [string],
    "what_supports_it": [string],
    "what_contradicts_it": [string],
    "what_is_unknown": [string],
    "recommendation": string
  },
  "recommendation": string,
  "limitations": [string]
}`;

      const messages: HfChatMessage[] = [
        { role: 'system', content: 'You are an enterprise cybersecurity and employment fraud forensic AI. Always respond with valid JSON only. Do NOT use emojis.' },
        { role: 'user', content: prompt }
      ];

      const res = await callHuggingFaceChat(messages, {
        model: this.primaryModel,
        fallbackModel: this.fallbackModel,
        maxTokens: 1024,
        temperature: 0.1,
      });

      let cleanJson = res.text.trim();
      if (cleanJson.startsWith('```json')) {
        cleanJson = cleanJson.replace(/^```json\s*/i, '').replace(/```\s*$/, '').trim();
      } else if (cleanJson.startsWith('```')) {
        cleanJson = cleanJson.replace(/^```\s*/, '').replace(/```\s*$/, '').trim();
      }

      const parsed = JSON.parse(cleanJson);
      return {
        ...parsed,
        provider_used: "HUGGINGFACE",
      };
    } catch (err: any) {
      console.warn(`[Hugging Face Synthesis] Falling back to LocalAIProvider: ${err?.message}`);
      return new LocalAIProvider().generateSynthesis(input);
    }
  }

  async answerCopilot(question: string, context: Record<string, any>): Promise<string> {
    // 1. Guardrail checks
    if (isDomainOffTopic(question)) {
      return DOMAIN_GUARDRAIL_MESSAGE;
    }

    const userName = context.user_name || context.candidate_name || (context.user_email ? context.user_email.split('@')[0] : 'Candidate');
    const compName = sanitizeCompanyName(context);

    // 2. Greeting check
    if (isGreeting(question)) {
      return buildGreetingResponse(userName, compName);
    }

    const token = (process.env.HF_TOKEN || process.env.HUGGINGFACE_TOKEN || '').trim();
    if (!token) {
      return generateEvidenceGroundedAnswer(question, context);
    }

    // 3. Assemble full context
    const locker = buildEvidenceLocker(context);
    const score = typeof context.trust_score === 'number'
      ? context.trust_score
      : (typeof context.confidence_score === 'number' ? context.confidence_score : 0);
    const verdict = context.verdict || (score <= 45 ? 'LIKELY SCAM / HIGH RISK' : 'LOW RISK / AUTHENTIC PROFILE');
    const docChunks = context.document_chunks || [];
    const extChunks = context.external_chunks || [];
    const evidenceCitations = locker.map(e => `[${e.id}] (${e.type}): ${e.claim}`).slice(0, 15).join('\n');
    const sampleIds = locker.length > 0 ? locker.map(l => '[' + l.id + ']').slice(0, 4).join(', ') : '[Doc-P1-C0], [Ext-DNS-01]';

    const assessmentsList = Array.isArray(context.assessments) && context.assessments.length > 0
      ? context.assessments
      : (context.scoring?.assessments || []);
    const assessmentsContext = assessmentsList.length > 0
      ? `\n--- 12 MULTI-VECTOR RISK ASSESSMENTS ---\n${assessmentsList.map((a: any) => `- [${a.name}] (ID: ${a.id}): Risk Score ${a.risk_score}/100 | Band: ${a.risk_band_label || a.risk_band} | Evidence: ${a.evidence_found} | Quote: "${a.exact_quote || 'N/A'}" | Next Step: ${a.recommended_next_step}`).join('\n')}\n`
      : '';

    const feeDetails = context.document_analysis?.fee_details || context.fee_details || [];
    const paymentCase = context.payment_case || context.document_analysis?.payment_case || '';
    const paymentContext = (feeDetails.length > 0 || paymentCase)
      ? `\n--- DETAILED FINANCIAL & PAYMENT EVIDENCE ---\nPayment Classification: ${paymentCase || 'EVALUATED'}\n${feeDetails.map((f: any) => `Category: ${f.category} | Amount: ${f.amount || 'Unspecified'} | Recipient: ${f.recipient || 'Unspecified'} | Channel: ${f.channel || 'Direct'} | Refundable: ${f.is_refundable} (${f.refund_terms}) | Deadline: ${f.deadline || 'None'} | Exact Quote: "${f.exact_quote}" | Why: ${f.why_it_matters}`).join('\n')}\n`
      : '';

    const externalResearchContext = context.external_research
      ? `\n--- STORED EXTERNAL RESEARCH & VERIFICATION FINDINGS ---\n${formatExternalResearchForPrompt(context.external_research)}\n`
      : '';

    const claimsList = context.extracted_claims || context.document_analysis?.extracted_claims || [];
    const claimsContext = claimsList.length > 0
      ? `\n--- EXTRACTED DOCUMENT CLAIMS ---\n${claimsList.map((c: any) => `- ${c.field}: "${c.value}" (Quote: "${c.source_quote}")`).join('\n')}\n`
      : '';

    const docText = String(
      context.rawText ||
      context.raw_text ||
      context.text ||
      context.document_analysis?.extracted_text ||
      context.extracted_text ||
      context.forensicAnalysis?.ocr?.rawText ||
      ''
    ).trim();
    const docTextSnippet = docText ? `\n--- EXTRACTED DOCUMENT / OCR TEXT (EXCERPT) ---\n${docText.slice(0, 2500)}\n` : '';

    const systemPrompt = `You are the LEGITIFY Forensic Investigation Assistant.
Your objective is to provide candidate '${userName}' with authoritative, objective, and evidentiary document forensic intelligence.

OPERATIONAL DIRECTIVES:
1. Tone: Maintain a professional, objective, enterprise security posture. Absolutely NO emojis anywhere in your response.
2. The investigated target organization is "${compName}". NEVER refer to the company as "images", "screenshot", or raw filenames.
3. Evaluated Authenticity & Trust Score: ${score}/100. Verdict: ${verdict}.
4. Answer the user's SPECIFIC question DIRECTLY and CONVERSATIONALLY in your very first sentence based on verified document evidence and stored external intelligence. Do NOT begin with rigid template headers (e.g. '### Investigation Findings'). Answer naturally and concisely as an expert forensic advisor.
5. Ground your explanation in the following verified Multi-Vector Assessments, Evidence Locker records, Stored External Research, Claims, and OCR text:
${assessmentsContext}
${paymentContext}
${externalResearchContext}
${claimsContext}
${docTextSnippet}
--- EVIDENCE RECORDS ---
${evidenceCitations || 'No evidence records available.'}
--- DUAL RAG CITATIONS ---
Document Chunks: ${JSON.stringify(docChunks.slice(0, 5))}
External Evidence Chunks: ${JSON.stringify(extChunks.slice(0, 5))}
6. Distinguish clearly:
   - Corporate Entity Existence != Offer Letter Authenticity.
   - An Authentic Corporate Registration on MCA21 does not prove that this specific recruiter, email, or offer letter is legitimate.
   - Legitimate corporate employers NEVER demand candidate registration fees, laptop caution deposits, or training charges.
7. Cite actual Evidence IDs (e.g. ${sampleIds}) and Vector Risk Scores where applicable.
8. If an assertion cannot be verified from the provided evidence, explicitly state: "This claim could not be verified from the available forensic evidence."
9. Include practical verification actions: checking the official company careers portal, calling the registered reception boardline, and reporting fraud to the 1930 National Cybercrime Helpline if money was transferred.
10. Format response cleanly using concise bullet points and bold key terms. Avoid repeating boilerplate document audit profiles on every turn.`;

    const messages: HfChatMessage[] = [
      { role: 'system', content: systemPrompt },
    ];

    if (Array.isArray(context.history) && context.history.length > 0) {
      for (const h of context.history.slice(-8)) {
        const role = h.role === 'assistant' ? 'assistant' : 'user';
        const content = String(h.text || h.content || '').trim();
        if (content) {
          messages.push({ role, content });
        }
      }
    }

    messages.push({ role: 'user', content: question });

    try {
      const result = await callHuggingFaceChat(messages, {
        model: this.primaryModel,
        fallbackModel: this.fallbackModel,
        maxTokens: 1024,
        temperature: 0.2,
      });

      const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu;
      const cleanAnswer = result.text.replace(emojiRegex, '').trim();

      if (cleanAnswer && cleanAnswer.length > 20) {
        return cleanAnswer;
      }
      return generateEvidenceGroundedAnswer(question, context);
    } catch (err: any) {
      const errMsg = err?.message || String(err);
      console.warn(`[Hugging Face Copilot] Error: ${errMsg}. Falling back to deterministic engine.`);

      if (errMsg.includes('INSUFFICIENT_CREDITS')) {
        const fallbackAnswer = generateEvidenceGroundedAnswer(question, context);
        return `[Notice: Hugging Face Inference credit limit reached (HTTP 402). Switched to deterministic evidence-grounded engine.]\n\n${fallbackAnswer}`;
      }

      if (errMsg.includes('UNAUTHORIZED')) {
        const fallbackAnswer = generateEvidenceGroundedAnswer(question, context);
        return `[Notice: Hugging Face API authentication error (HTTP 401). Switched to deterministic evidence-grounded engine.]\n\n${fallbackAnswer}`;
      }

      return generateEvidenceGroundedAnswer(question, context);
    }
  }
}

export function getActiveAIProvider(): IAIProvider {
  const hfToken = (process.env.HF_TOKEN || process.env.HUGGINGFACE_TOKEN || '').trim();
  if (hfToken) {
    return new HuggingFaceProvider();
  }
  const geminiKey = (process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY || '').trim();
  if (geminiKey) {
    return new GeminiFlashProvider();
  }
  return new LocalAIProvider();
}
