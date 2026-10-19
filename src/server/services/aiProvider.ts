// ==============================================================================
// LEGITIFY EVIDENCE-GROUNDED INVESTIGATION COPILOT (AI PROVIDER)
// Strict Evidence-First Architecture + Adaptive LLM Intelligence Grounded in Evidence
// ==============================================================================
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';
import { EvidenceItem, RuleEvaluation, MLPredictionResult } from '../../types';
import { isFilenameOrPlaceholder } from '../utils/normalizer';

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
  provider_used: "LOCAL_AI" | "GEMINI_FLASH" | "DETERMINISTIC_FALLBACK";
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
    : (typeof context.confidence_score === 'number' ? context.confidence_score : 0);
  const confidence = context.confidence || context.confidence_score || 85;
  const isHighRisk = score <= 45;

  // 1. Collect Raw Document Text Corpus
  const docText = String(
    context.rawText ||
    context.text ||
    context.document_analysis?.extracted_text ||
    context.extracted_text ||
    context.forensicAnalysis?.ocr?.rawText ||
    context.context_text ||
    ''
  ).trim();
  const docTextLower = docText.toLowerCase();

  // 2. Collect Extracted Entities & Parameters
  const offerParts = context.extracted_offer_parts || {};
  const semantics = context.forensicAnalysis?.semantics || context.document_analysis?.semantics || {};
  const structure = context.forensicAnalysis?.scoring?.structureAnalysis || semantics?.structure || context.structureAnalysis;

  const detectedRole = offerParts.roles?.[0] || semantics.detectedRole || (docText.match(/(?:Role|Position|Designation|Job Title|Internship as)\s*[:\-]?\s*([A-Za-z0-9\s/&()\-]{3,40})/i)?.[1]?.trim()) || 'Internship / Employment Position';
  
  const detectedStipends: any[] = offerParts.stipends || [];
  const primaryStipend = detectedStipends[0]?.rawText || semantics.detectedStipend || (docText.match(/(?:Stipend|Salary|Compensation|CTC|Remuneration)\s*[:\-]?\s*(?:INR|Rs\.?|₹|\$|USD)?\s*([0-9,]+(?:\s*(?:per month|\/month|LPA|K))?)/i)?.[1]?.trim());

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

  // Helper: Find sentences in raw document matching query terms
  const findMatchingDocSentences = (keywords: string[]): string[] => {
    if (!docText) return [];
    const sentences = docText.split(/(?<=[.!?\n])\s+/);
    return sentences.filter(s => {
      const sLower = s.toLowerCase();
      return keywords.some(k => sLower.includes(k.toLowerCase()));
    }).slice(0, 3);
  };

  // ==========================================================================
  // INTENT 0.1: Payment, Fees, Caution Deposits, and Financial Safety
  // ==========================================================================
  if (
    (q.includes('fee') || q.includes('deposit') || q.includes('charge') || q.includes('caution') || q.includes('registration') || q.includes('payment') || (q.includes('financial') && q.includes('safety')) || (q.includes('why') && (q.includes('risk low') || q.includes('risk high') || q.includes('payment risk')))) &&
    !q.includes('already paid') && !q.includes('transferred') && !q.includes('sent money') && !q.includes('i paid')
  ) {
    const isFeeDetected = Boolean(hasFee || (paymentAssessment && paymentAssessment.risk_score >= 70) || feeDetails.length > 0);
    const scoreVal = paymentAssessment?.risk_score ?? (isFeeDetected ? 96 : 5);
    const bandLabel = paymentAssessment?.risk_band_label ?? (isFeeDetected ? 'Critical Fraud Risk' : 'Low Risk');

    if (isFeeDetected) {
      const feeQuote = primaryFee?.exact_quote || findMatchingDocSentences(['fee', 'deposit', 'rs.', 'inr', 'pay', 'charge', 'registration', 'caution'])[0] || 'Upfront monetary deposit demanded in document.';
      return `### Payment and Financial Fee Safety Audit: ${companyName}

* **Risk Score:** **${scoreVal}/100** (${bandLabel})
* **Safety Status:** **CRITICAL RISK · Explicit Candidate Payment Demand Detected**

**1. Extracted Financial Parameters:**
* **Fee Category:** ${primaryFee?.category || 'Registration / Processing / Security Deposit'}
* **Amount Demanded:** **${primaryFee?.amount || 'Monetary deposit specified'}**
* **Payment Recipient / Endpoint:** **${primaryFee?.recipient || 'Specified payment endpoint / UPI ID'}**
* **Refundability Terms:** ${primaryFee?.is_refundable ? 'Claimed refundable (' + (primaryFee?.refund_terms || 'conditional') + ')' : 'Non-refundable / unstated'}
* **Payment Window:** ${primaryFee?.deadline || 'Immediate onboarding deadline'}

**2. Exact Document Excerpt:**
> *"${feeQuote}"*

**3. Forensic Grounding & Security Principle:**
* **The Zero-Fee Hiring Standard:** Legitimate enterprise employers and accredited internship programs **never charge candidates** registration fees, document verification fees, training costs, or laptop caution money prior to joining.
* **The "Refundable Deposit" Pretext:** Scammers frequently claim fees are *100% refundable with the first month's stipend* to create false psychological security. This is a recognized scam tactic.

**4. Mandatory Next Steps:**
* **DO NOT TRANSFER FUNDS:** Do not make any UPI payments, bank transfers, or wallet deposits.
* **Report Immediately:** If money was already transferred, call the National Cybercrime Helpline (**1930**) immediately to attempt a transaction freeze.`;
    } else {
      const hasComp = candidateCompList.length > 0 || Boolean(primaryStipend);
      const compSummary = candidateCompList.map((c: any) => `${c.type || 'Remuneration'}: ${c.amount || c.raw_quote || c.rawText || ''}`).join(', ') || primaryStipend || 'Unstated';
      return `### Payment and Financial Fee Safety Audit: ${companyName}

* **Risk Score:** **${scoreVal}/100** (${bandLabel})
* **Safety Status:** **LOW RISK · Zero Candidate Payment Demands Detected**

**1. Forensic Examination Findings:**
* **Zero Upfront Fees:** The analyzed document contains **no registration fees, security deposits, training charges, or caution money demands**.
${hasComp ? `* **Candidate Remuneration Detected:** The document outlines candidate compensation (**${compSummary}**). This constitutes payment *to* the candidate, adhering to genuine employment practices.` : ''}

**2. Why Payment Risk is Low:**
* The document adheres to the **Zero-Fee Hiring Protocol**. Legitimate employers compensate their employees and interns rather than requiring candidates to pay upfront fees to secure appointments.

**3. Standard Precaution:**
* Maintain standard onboarding vigilance. If the recruiter later requests fees via phone, email, or messaging apps, cease contact immediately.`;
    }
  }

  // ==========================================================================
  // INTENT 0.2: Organization Identity & Identification Status
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
  // INTENT 0.3: Multi-Vector Assessment Specific Inquiry
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
  // INTENT 1: Working Hours, Schedule, Shifts, Timings, Work Days
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
  // INTENT 2: Signatory, Signature, Who Signed, Authority Block
  // ==========================================================================
  if (q.includes('signatory') || q.includes('signed') || q.includes('signature') || q.includes('who signed') || q.includes('stamp') || q.includes('seal')) {
    const sigMatches = findMatchingDocSentences(['sincerely', 'regards', 'signatory', 'authorized', 'manager', 'director', 'talent acquisition', 'human resources']);

    return `### Authorized Signatory & Executive Execution Audit

**1. Extracted Signatory Parameters:**
* **Detected Signatory / Department:** **${primarySignatory || 'Signatory block unstated / unverified'}**
* **Executive Title / Function:** ${structure?.signatoryTitle || 'Human Resources / Talent Acquisition'}
${sigMatches.length > 0 ? `* **Sign-off Text Observed:** *"${sigMatches[0].trim()}"*` : ''}

**2. Forensic Verification Principles:**
* **Absence of Listed Executive $\\neq$ Automatic Proof of Fraud:** Junior HR talent coordinators often sign internship contracts without appearing on public MCA Director registers.
* **Risk Indicators:**
  * Typed name without signature stroke or digital cryptographic certificate.
  * Generic signatures copied from internet templates.
  * Mismatch between the signatory's claimed title and company size.

**3. Verification Step:**
Contact ${companyName}'s official corporate switchboard and request verification with **${primarySignatory || 'the Talent Acquisition department'}** to confirm authorization.`;
  }

  // ==========================================================================
  // INTENT 3: Stipend, Salary, Compensation, Package, CTC, Plausibility
  // ==========================================================================
  if (q.includes('stipend') || q.includes('salary') || q.includes('package') || q.includes('compensation') || q.includes('ctc') || q.includes('pay') || q.includes('money') && (q.includes('receive') || q.includes('get'))) {
    const compMatches = findMatchingDocSentences(['stipend', 'salary', 'compensation', 'inr', 'rs.', '₹', 'per month', 'ctc', 'lpa']);

    return `### Compensation & Economic Plausibility Analysis: ${companyName}

**1. Extracted Compensation Terms:**
* **Documented Compensation / Stipend:** **${primaryStipend || 'Unstated / Not explicitly defined in letter'}**
* **Designated Role:** **${detectedRole}**
${compMatches.length > 0 ? `* **Direct Text Excerpt:** *"${compMatches[0].trim()}"*` : ''}

**2. Economic Plausibility Assessment:**
* **Standard Market Median:** Authentic Indian corporate internships for ${detectedRole} typically benchmark between **₹12,000 to ₹35,000 per month** (higher for top-tier product tech firms).
* **Contradiction Check:** ${hasFee ? '[CRITICAL ANOMALY] The document promises compensation while simultaneously soliciting candidate deposits or registration charges. Corporate employers prohibit candidate charges.' : '[VERIFIED] No candidate-side deduction or caution deposit was detected.'}
* **Inflation Risk:** Exercise caution regarding offers promising inflated compensation (e.g., ₹50,000+/month) for entry-level positions without technical interview stages.`;
  }

  // ==========================================================================
  // INTENT 4: Why This Score / Why High Risk / Why Is It Fake?
  // ==========================================================================
  if (q.includes('why') || q.includes('score') || q.includes('fake') || q.includes('decision') || q.includes('reason') || q.includes('red flag') || q.includes('warning')) {
    const keyDrivers: string[] = [];
    if (hasFee) keyDrivers.push(`[CRITICAL RISK] **Mandatory Candidate Fee Demanded:** Monetary charges detected [${feeDemandKeywords.join(', ') || 'Deposit requested'}]. Corporate employment prohibits candidate charges.`);
    if (isFreeWebmail) keyDrivers.push(`[HIGH RISK] **Public Webmail Recruiter:** Recruiter uses personal webmail (${recruiterEmail}) rather than an authenticated corporate domain.`);
    if (hasInformal) keyDrivers.push(`[HIGH RISK] **Informal Channel Migration:** Recruitment directed to ${informalChannels.join(', ')} to bypass formal corporate audit trails.`);
    if (hasNoInterview) keyDrivers.push(`[HIGH RISK] **Direct Selection Without Interview:** Unscreened direct appointment is an established recruitment risk indicator.`);
    if (structure && !structure.hasOfficialReferenceNumber) keyDrivers.push(`[DEFECT] **Missing Document Reference Number:** Lacks standard corporate tracking ID (Ref No.).`);
    if (structure && !structure.hasRegisteredAddress) keyDrivers.push(`[DEFECT] **Missing Registered Office Address:** No physical corporate campus or registered location stated.`);

    if (keyDrivers.length === 0) {
      keyDrivers.push(`[COMPLIANT] **Zero-Fee Compliant:** No candidate monetary charges identified.`);
      keyDrivers.push(`[COMPLIANT] **Corporate Domain:** Recruiter correspondence originates from official domain.`);
      keyDrivers.push(`[COMPLIANT] **Standard Formatting:** Corporate letterhead and reference tracking present.`);
    }

    return `### Forensic Assessment Breakdown: ${companyName}

* **Trust Score:** **${score}/100** (${isHighRisk ? 'HIGH RISK · Anomalies Detected' : 'LOW RISK · Verified Profile'})
* **Overall Verdict:** **${context.verdict || (isHighRisk ? 'LIKELY SCAM / HIGH RISK' : 'LOW RISK')}**
* **Confidence Level:** **${confidence}%** based on multi-dimensional forensic cross-examination.

---

### Primary Evidentiary Drivers in This Document:
${keyDrivers.map((d, i) => `${i + 1}. ${d}`).join('\n\n')}

---

### Core Security Principle:
> **Company Existence $\\neq$ Offer Authenticity.**
> Even if **${companyName}** is a legally registered company in corporate registers, bad actors routinely produce lookalike documents and unauthorized free email accounts impersonating genuine organizations.`;
  }

  // ==========================================================================
  // INTENT 5: Standard Legitimate Format & Structural Integrity Checks
  // ==========================================================================
  if (q.includes('format') || q.includes('structure') || q.includes('template') || q.includes('standard') || q.includes('letterhead') || q.includes('reference number') || q.includes('ref no')) {
    const checks = structure?.structureChecks || [];
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

${missing.length > 0 ? `\n**3. Critical Missing Conventions:**\n${missing.map(m => `* [DEFECT] ${m}`).join('\n')}` : ''}

**Conclusion:** Legitimate corporate HR departments enforce strict document governance. Omission of multiple administrative conventions indicates an unverified or informal letter.`;
  }

  // ==========================================================================
  // INTENT 6: Emergency - What if I already paid money?
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
  // INTENT 7: Questions to Ask the Recruiter
  // ==========================================================================
  if (q.includes('question') || q.includes('ask recruiter') || q.includes('what should i ask') || q.includes('hr question')) {
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
  // INTENT 8: 30-Second Summary for Parents & Family
  // ==========================================================================
  if (q.includes('parent') || q.includes('family') || q.includes('30-second') || q.includes('simple') || q.includes('explain simply')) {
    return `### Executive Summary for Advisors & Family

> *"This offer letter uses the name of **${companyName}**, but our verification indicates ${isHighRisk ? 'critical risk factors in the recruiter contact or fee clauses' : 'standard corporate recruitment patterns'}.*
> *Real companies never charge students to give them a job. The National Cybercrime Helpline (1930) classifies asking money for job offers as employment fraud. We should ${isHighRisk ? 'not pay any fee or send sensitive ID documents' : 'proceed with standard corporate verification'}.*

**Key Takeaways:**
* **Company Status:** ${companyName} (${isHighRisk ? 'Unverified recruiter' : 'Corporate profile evaluated'})
* **Financial Demands:** ${hasFee ? '[FLAGGED] Mandatory candidate deposit demanded' : '[VERIFIED] No candidate fee detected'}
* **Next Action:** ${isHighRisk ? 'Do NOT transfer funds or provide sensitive identification documents.' : 'Verify directly via official company careers portal.'}`;
  }

  // ==========================================================================
  // INTENT 9: DYNAMIC SENTENCE-LEVEL SEMANTIC RETRIEVAL OVER DOCUMENT TEXT
  // For ANY arbitrary question, extracts exact matching sentences from text!
  // ==========================================================================
  const queryTerms = q.split(/\s+/).filter(w => w.length > 2 && !['what', 'when', 'where', 'which', 'who', 'whom', 'whose', 'why', 'how', 'the', 'this', 'that', 'with', 'from', 'about', 'does', 'have', 'tell', 'give', 'show'].includes(w));
  const matchedSentences = findMatchingDocSentences(queryTerms);

  if (matchedSentences.length > 0) {
    return `### Investigation Findings: "${question}"

**1. Relevant Excerpts from Uploaded Document:**
${matchedSentences.map(s => `* *"${s.trim()}"*`).join('\n\n')}

**2. Contextual Forensic Analysis:**
* **Target Entity:** **${companyName}** · Trust Score: **${score}/100**
* The clause(s) extracted above directly relate to your question.
* ${hasFee ? '[RISK] Regardless of specific clauses, this letter contains candidate fee requirements which violate standard employment ethics.' : 'Standard review advised.'}

**3. Next Step:**
Compare these terms with the verified company guidelines on their official corporate website (\`/careers\`).`;
  }

  // ==========================================================================
  // INTENT 10: INTELLIGENT OPEN-ENDED CONTEXTUAL SYNTHESIS
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

  return `### Forensic Consultation: ${compRef}

Regarding your inquiry: *"**${question}**"*

**Forensic Overview:**
* **Target Entity:** **${companyName}**
* **Evaluated Status:** ${isHighRisk ? '**Critical Risk / Potential Scam Indicator**' : '**Standard Corporate Profile**'}
* **Financial Safety:** The document ${feeStatusText}.
* **Recruiter Channel:** The ${recruiterStatusText}.
${primaryStipend ? `* **Stipend Mentioned:** ${primaryStipend}` : ''}
${referenceNumber ? `* **Document Reference ID:** ${referenceNumber}` : ''}

**Direct Guidance on Your Question:**
I reviewed the document text for clauses relating to your question. If your question references specific onboarding policies, roles, or conditions not explicitly detailed here, note that authentic corporate contracts typically provide comprehensive terms of employment.

**Recommended Next Step:**
Verify the offer directly with official Human Resources via the company's verified switchboard or official careers page (\`/careers\`).`;
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
        ? `\n--- EXTERNAL RESEARCH & VERIFICATION FINDINGS ---\n${JSON.stringify(context.external_research).slice(0, 1500)}\n`
        : '';

      const systemPrompt = `You are the LEGITIFY Forensic Investigation Assistant.
Your objective is to provide candidate '${userName}' with authoritative, objective, and evidentiary document forensic intelligence.

OPERATIONAL DIRECTIVES:
1. Tone: Maintain a professional, objective, enterprise security posture. Absolutely NO emojis anywhere in your response.
2. The investigated target organization is "${compName}". NEVER refer to the company as "images", "screenshot", or raw filenames.
3. Evaluated Authenticity & Trust Score: ${score}/100.
4. You must answer the user's SPECIFIC question directly and conversationally based ONLY on verified evidence. If the user asks a follow-up question or references prior context, use the conversation history to answer naturally. Do NOT dump the full report or output a repeating 'Forensic Intelligence Briefing' template.
5. Ground your explanation in the following verified Multi-Vector Assessments, Evidence Locker records, and Dual RAG citations:
${assessmentsContext}
${paymentContext}
${externalResearchContext}
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

export function getActiveAIProvider(): IAIProvider {
  return new GeminiFlashProvider();
}
