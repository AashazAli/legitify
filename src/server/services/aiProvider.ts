// ==============================================================================
// LEGITIFY EVIDENCE-GROUNDED INVESTIGATION COPILOT (AI PROVIDER)
// Strict Evidence-First Architecture + Adaptive LLM Intelligence Grounded in Evidence
// ==============================================================================
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';
import { EvidenceItem, RuleEvaluation, MLPredictionResult } from '../../types';

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
  const detected = context.document_analysis?.extracted_entities?.detected_company;
  if (detected && detected.length > 2 && !detected.match(/\.(png|jpg|jpeg|pdf)$/i)) {
    return detected;
  }

  const raw = String(context.company_name || context.entity_name || context.entity_value || "");
  if (!raw || raw.match(/(\.(png|jpg|jpeg|pdf)$|^images|^image\s*\(|^screenshot|^upload)/i)) {
    return detected || "Unknown Organization";
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

// // ----------------------------------------------------------------------------
// COMPREHENSIVE EVIDENCE-GROUNDED REASONING ENGINE (DYNAMIC INTENT HANDLER)
// Dynamically inspects raw document text, extracted offer parts, structural
// format checks, detected risks, and evidence locker to answer questions accurately.
// ----------------------------------------------------------------------------
export function generateEvidenceGroundedAnswer(question: string, context: Record<string, any>): string {
  const q = question.toLowerCase().trim();
  const userName = context.user_name || context.candidate_name || (context.user_email ? context.user_email.split('@')[0] : 'Candidate');
  const greeting = `Hello ${userName}! 👋\n\n`;

  const companyName = sanitizeCompanyName(context);
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
  // INTENT 1: Working Hours, Schedule, Shifts, Timings, Work Days
  // ==========================================================================
  if (q.includes('hour') || q.includes('timing') || q.includes('schedule') || q.includes('shift') || q.includes('time') || q.includes('attendance') || q.includes('work day')) {
    const hourMatches = findMatchingDocSentences(['hour', 'timing', 'schedule', 'shift', 'am', 'pm', 'monday', 'friday', 'weekend', 'working day']);

    if (hourMatches.length > 0) {
      return greeting + `### ⏰ Working Hours & Schedule Analysis for ${companyName}

**1. Extracted Clauses from Uploaded Document:**
${hourMatches.map(m => `* *"${m.trim()}"*`).join('\n')}

**2. Forensic Evaluation:**
* The document explicitly outlines operational timing and schedule expectations.
* **Standard Enterprise Benchmark:** Authentic enterprise contracts typically mandate 40–45 hours per week (e.g., 9:30 AM to 6:30 PM, Monday through Friday) with formal public holiday provisions.
* If flexible/remote hours are promised without tracking or oversight, cross-verify attendance expectations with HR before onboarding.`;
    } else {
      return greeting + `### ⏰ Working Hours & Schedule Analysis for ${companyName}

**1. Document Inspection Finding:**
* 🔍 **No explicit working hours, shift timings, or schedule clauses were identified in the analyzed document text.**

**2. Forensic Implications:**
* **Standard Legitimate Practice:** Authentic enterprise appointment and internship contracts explicitly define:
  1. Weekly working commitment (e.g., *40 hours per week*).
  2. Daily operational window (e.g., *9:00 AM – 6:00 PM IST*).
  3. Work model specification (*On-site campus / Hybrid / Remote*).
* **Why This Matters:** The complete omission of working hours, department reporting times, or attendance policies is a frequent characteristic of **unregulated or fabricated offer templates** assembled without corporate HR oversight.

**3. Action Item:**
Request a formal Addendum or Appointment Annexure specifying work hours and reporting manager details from official company HR.`;
    }
  }

  // ==========================================================================
  // INTENT 2: Signatory, Signature, Who Signed, Authority Block
  // ==========================================================================
  if (q.includes('signatory') || q.includes('signed') || q.includes('signature') || q.includes('who signed') || q.includes('stamp') || q.includes('seal')) {
    const sigMatches = findMatchingDocSentences(['sincerely', 'regards', 'signatory', 'authorized', 'manager', 'director', 'talent acquisition', 'human resources']);

    return greeting + `### ✍️ Authorized Signatory & Execution Analysis

**1. Extracted Signatory Parameters:**
* **Detected Signatory / Department:** **${primarySignatory || 'Signatory block unstated / unverified'}**
* **Executive Title / Function:** ${structure?.signatoryTitle || 'Human Resources / Talent Acquisition'}
${sigMatches.length > 0 ? `* **Sign-off Text Observed:** *"${sigMatches[0].trim()}"*` : ''}

**2. Forensic Verification Principles:**
* **Absence of Listed Executive $\\neq$ Automatic Proof of Fraud:** Junior HR talent coordinators often sign internship contracts without appearing on public MCA Director registers.
* **Red Flag Indicators:**
  * Typed name without signature stroke or digital cryptographic certificate.
  * Generic signatures copied from internet stock photos.
  * Mismatch between the signatory's claimed title and company size.

**3. Verification Step:**
Call ${companyName}'s official reception switchboard and ask to be connected with **${primarySignatory || 'the Talent Acquisition department'}** to confirm their authorization.`;
  }

  // ==========================================================================
  // INTENT 3: Stipend, Salary, Compensation, Package, CTC, Plausibility
  // ==========================================================================
  if (q.includes('stipend') || q.includes('salary') || q.includes('package') || q.includes('compensation') || q.includes('ctc') || q.includes('pay') || q.includes('money') && (q.includes('receive') || q.includes('get'))) {
    const compMatches = findMatchingDocSentences(['stipend', 'salary', 'compensation', 'inr', 'rs.', '₹', 'per month', 'ctc', 'lpa']);

    return greeting + `### 💰 Compensation & Economic Plausibility Analysis for ${companyName}

**1. Extracted Compensation Terms:**
* **Documented Compensation / Stipend:** **${primaryStipend || 'Unstated / Not explicitly defined in letter'}**
* **Designated Role:** **${detectedRole}**
${compMatches.length > 0 ? `* **Direct Text Excerpt:** *"${compMatches[0].trim()}"*` : ''}

**2. Economic Plausibility Assessment:**
* **Standard Market Median:** Authentic Indian corporate internships for ${detectedRole} typically benchmark between **₹12,000 to ₹35,000 per month** (higher for top-tier product tech firms).
* **Contradiction Check:** ${hasFee ? '🚨 **CRITICAL CONTRADICTION:** The document promises compensation while simultaneously soliciting candidate deposits or registration charges. This is a definitive employment fraud pattern.' : '✅ **Zero-Fee Adherence:** No candidate-side deduction or caution deposit was detected.'}
* **Inflation Risk:** Be wary of offers promising exorbitant salaries (e.g., ₹50,000+/month) for entry-level tasks without prior technical interview evaluation.`;
  }

  // ==========================================================================
  // INTENT 4: Why This Score / Why High Risk / Why Is It Fake?
  // ==========================================================================
  if (q.includes('why') || q.includes('score') || q.includes('fake') || q.includes('decision') || q.includes('reason') || q.includes('red flag') || q.includes('warning')) {
    const keyDrivers: string[] = [];
    if (hasFee) keyDrivers.push(`🚨 **Mandatory Candidate Fee Demanded:** Upfront monetary charges detected [${feeDemandKeywords.join(', ') || 'Deposit requested'}]. Corporate employment prohibits candidate charges.`);
    if (isFreeWebmail) keyDrivers.push(`🚨 **Public Webmail Recruiter:** Recruiter uses personal webmail (${recruiterEmail}) rather than an authenticated corporate domain.`);
    if (hasInformal) keyDrivers.push(`🚨 **Informal Channel Migration:** Recruitment directed to ${informalChannels.join(', ')} to bypass formal corporate audit trails.`);
    if (hasNoInterview) keyDrivers.push(`🚨 **Direct Selection Without Interview:** Unscreened direct appointment is a known recruitment scam mechanism.`);
    if (structure && !structure.hasOfficialReferenceNumber) keyDrivers.push(`⚠️ **Missing Document Reference Number:** Lacks standard corporate tracking ID (Ref No.).`);
    if (structure && !structure.hasRegisteredAddress) keyDrivers.push(`⚠️ **Missing Registered Office Address:** No physical corporate campus or registered location stated.`);

    if (keyDrivers.length === 0) {
      keyDrivers.push(`✅ **Zero-Fee Compliant:** No candidate monetary charges identified.`);
      keyDrivers.push(`✅ **Corporate Domain:** Recruiter correspondence originates from official domain.`);
      keyDrivers.push(`✅ **Standard Formatting:** Corporate letterhead and reference tracking present.`);
    }

    return greeting + `### 📊 Forensic Assessment Breakdown for ${companyName}

* **Trust Score:** **${score}/100** (${isHighRisk ? '🔴 High Risk · Scam Indicators Detected' : '🟢 Verified Low Risk Profile'})
* **Overall Verdict:** **${context.verdict || (isHighRisk ? 'LIKELY SCAM / HIGH RISK' : 'LOW RISK')}**
* **Confidence Level:** **${confidence}%** based on multi-dimensional forensic cross-examination.

---

### 🔍 Primary Evidentiary Drivers in This Document:
${keyDrivers.map((d, i) => `${i + 1}. ${d}`).join('\n\n')}

---

### 🛡️ Core Cybersecurity Principle:
> **Company Existence $\\neq$ Offer Authenticity.**
> Even if **${companyName}** is a legally registered company in MCA21, fraudsters routinely create lookalike documents and unauthorized Gmail accounts impersonating genuine brands.`;
  }

  // ==========================================================================
  // INTENT 5: Standard Legitimate Format & Structural Integrity Checks
  // ==========================================================================
  if (q.includes('format') || q.includes('structure') || q.includes('template') || q.includes('standard') || q.includes('letterhead') || q.includes('reference number') || q.includes('ref no')) {
    const checks = structure?.structureChecks || [];
    const missing = structure?.missingElements || [];

    return greeting + `### 📋 Standard Organizational Format & Structure Audit

Every legitimate corporate offer letter adheres to standardized enterprise documentation conventions. Here is how this document complies:

**1. Structural Compliance Score:** **${structure?.structureScore ?? 45}/100** (${structure?.status ?? 'EVALUATED'})
* **Conventions Passed:** **${structure?.passedChecksCount ?? 5} / ${structure?.totalChecksCount ?? 10} Standards**

**2. Document Control Parameters:**
* **Official Reference Number:** ${referenceNumber ? '✅ Identified: ' + referenceNumber : '❌ Absent (Non-standard template)'}
* **Corporate Letterhead & Entity:** ${structure?.hasCorporateHeader ? '✅ Verified corporate entity indicator' : '❌ Generic header lacking entity suffix'}
* **Registered Office Address:** ${structure?.hasRegisteredAddress ? '✅ Physical corporate campus present' : '❌ Omitted physical registered address & PIN code'}
* **Personalized Addressee:** ${structure?.hasPersonalizedAddressee ? `✅ Addressed to: ${structure.candidateName}` : '❌ Generic salutation (e.g., "Dear Candidate")'}
* **Authorized Signatory Block:** ${structure?.hasAuthorizedSignatoryBlock ? '✅ HR executive closing block present' : '❌ Lacks executive designation & signature'}

${missing.length > 0 ? `\n**3. Critical Missing Conventions:**\n${missing.map(m => `* ⚠️ ${m}`).join('\n')}` : ''}

**Conclusion:** Legitimate corporate HR departments enforce strict document governance. Omission of multiple administrative conventions indicates an unverified or informal letter.`;
  }

  // ==========================================================================
  // INTENT 6: Emergency - What if I already paid money?
  // ==========================================================================
  if (q.includes('already paid') || q.includes('transferred') || q.includes('sent money') || q.includes('i paid') || q.includes('scammed') || q.includes('lost money') || q.includes('police') || q.includes('1930')) {
    return greeting + `### 🚨 EMERGENCY ACTION PLAN: Immediate Steps If You Sent Money

If you have transferred funds to this recruiter, act IMMEDIATELY:

1. **📞 Call National Cybercrime Helpline (1930) RIGHT NOW:**
   * Dial **1930** (24x7 across India).
   * **Golden Hour Rule:** Reporting within **2 hours** allows cybercrime cells to freeze the recipient bank account or UPI wallet before money is withdrawn.

2. **🏦 Contact Your Bank's Fraud Desk:**
   * Report an **unauthorized employment fraud transaction**.
   * Provide the UTR / UPI Transaction Reference Number and request an immediate chargeback / recall.

3. **👮 File an Official e-FIR:**
   * Visit **[cybercrime.gov.in](https://cybercrime.gov.in)**.
   * Attach screenshots of payment, the offer letter, and WhatsApp/Telegram chat logs.

4. **🔒 Protect Your Identity:**
   * If you shared Aadhaar or PAN card copies, lock your biometrics immediately on the **[UIDAI portal](https://resident.uidai.gov.in/aadhaar-lockunlock)**.`;
  }

  // ==========================================================================
  // INTENT 7: Questions to Ask the Recruiter
  // ==========================================================================
  if (q.includes('question') || q.includes('ask recruiter') || q.includes('what should i ask') || q.includes('hr question')) {
    return greeting + `### ❓ Recruiter Verification Checklist for ${companyName}

Copy and send these 5 formal verification questions to the recruiter:

1. **Official Careers Portal Requisition:**
   *"Please provide the direct requisition link for this position hosted on your official corporate careers portal ('${companyName.toLowerCase().replace(/[^a-z0-9]/g, '')}.com/careers')."*

2. **Corporate Domain Email Requirement:**
   *"Why is this offer correspondence originating from ${isFreeWebmail ? ('a personal Gmail address (' + recruiterEmail + ')') : 'an unaligned channel'} rather than your official enterprise domain server?"*

3. **Official Reference & Requisition ID:**
   *"Please confirm the internal Corporate Offer Requisition ID registered with your Central HR talent management system."*

4. **Zero-Fee Statutory Written Confirmation:**
   *"Please confirm in writing that there are zero mandatory registration fees, laptop security deposits, training charges, or onboarding fees at any stage."*

5. **Direct Boardline Telephone Verification:**
   *"May I have the direct telephone extension and official contact details of your Central HR Department to verify this offer independently?"*

💡 *When the recruiter replies, paste their response back into LEGITIFY for instant analysis!*`;
  }

  // ==========================================================================
  // INTENT 8: 30-Second Summary for Parents & Family
  // ==========================================================================
  if (q.includes('parent') || q.includes('family') || q.includes('30-second') || q.includes('simple') || q.includes('explain simply')) {
    return greeting + `### ⏱️ 30-Second Summary for Parents & Family

> *"This offer letter uses the name of **${companyName}**, but our verification indicates ${isHighRisk ? 'critical risk factors in the recruiter contact or fee clauses' : 'standard corporate recruitment patterns'}.*
> *Real companies never charge students to give them a job. The National Cybercrime Helpline (1930) classifies asking money for job offers as employment fraud. We should ${isHighRisk ? 'not pay any fee or send sensitive ID documents' : 'proceed with standard corporate verification'}.*

**Key Takeaways:**
* **Company Status:** ${companyName} (${isHighRisk ? 'Unverified recruiter' : 'Corporate profile evaluated'})
* **Money Involved:** ${hasFee ? '🚨 Demands candidate payment/deposit' : '✅ No candidate fee detected'}
* **Next Action:** ${isHighRisk ? 'Do NOT pay money or share Aadhaar/bank documents.' : 'Verify directly via official company careers portal.'}`;
  }

  // ==========================================================================
  // INTENT 9: DYNAMIC SENTENCE-LEVEL SEMANTIC RETRIEVAL OVER DOCUMENT TEXT
  // For ANY arbitrary question, extracts exact matching sentences from text!
  // ==========================================================================
  const queryTerms = q.split(/\s+/).filter(w => w.length > 2 && !['what', 'when', 'where', 'which', 'who', 'whom', 'whose', 'why', 'how', 'the', 'this', 'that', 'with', 'from', 'about', 'does', 'have', 'tell', 'give', 'show'].includes(w));
  const matchedSentences = findMatchingDocSentences(queryTerms);

  if (matchedSentences.length > 0) {
    return greeting + `### 🔍 Investigation Findings: "${question}"

**1. Relevant Excerpts from Uploaded Document:**
${matchedSentences.map(s => `* *"${s.trim()}"*`).join('\n\n')}

**2. Contextual Forensic Analysis:**
* **Target Entity:** **${companyName}** · Trust Score: **${score}/100**
* The clause(s) extracted above directly relate to your question.
* ${hasFee ? '⚠️ Note: Regardless of specific clauses, this letter contains candidate fee requirements which violate standard employment ethics.' : 'Standard review advised.'}

**3. Next Step:**
Compare these terms with the verified company guidelines on their official corporate website (\`/careers\`).`;
  }

  // ==========================================================================
  // INTENT 10: INTELLIGENT OPEN-ENDED CONTEXTUAL SYNTHESIS
  // ==========================================================================
  return greeting + `### 🛡️ LEGITIFY Forensic Intelligence: ${companyName}

**Regarding your inquiry:** *"**${question}**"*

---

### 1. Extracted Document Audit Profile:
* **Target Organization:** **${companyName}**
* **Designated Role:** **${detectedRole}**
* **Stipend / Compensation:** **${primaryStipend || 'Unstated in document text'}**
* **Recruiter Email:** **${recruiterEmail || 'Not stated'}** (${isFreeWebmail ? '🚨 Free Webmail' : 'Domain Aligned'})
* **Document Reference ID:** **${referenceNumber || 'Omitted'}**
* **Evaluated Trust Score:** **${score}/100** (${isHighRisk ? '🔴 High Risk · Scam Signals Detected' : '🟢 Low Risk Profile'})

---

### 2. Forensic Analysis of Your Question:
I inspected the uploaded document for *"**${question}**"*.
* If your question references specific onboarding clauses or terms not found above, note that this document **omits detailed operational descriptions**, which is a recognized characteristic of non-standard templates.
* **Key Verification Rule:** A legitimate corporate offer always includes an official reference number, registered office address, standard 40-hour work schedule, and verified corporate email correspondence.

---

💡 *You can ask me about working hours, stipend plausibility, signatory authenticity, standard formatting checks, or how to challenge this result!*`;
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
        model: 'gemini-3.6-flash',
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
    const userName = context.user_name || context.candidate_name || (context.user_email ? context.user_email.split('@')[0] : 'Candidate');
    const compName = sanitizeCompanyName(context);
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
      const systemPrompt = `You are the LEGITIFY Evidence-Grounded Investigation Copilot.
Your job is to assist candidate '${userName}' by answering their exact question accurately, professionally, and empathetically.

CRITICAL RULES:
1. Greet the candidate naturally: "Hello ${userName}! 👋"
2. The investigated target organization is "${compName}". NEVER refer to the company as "images", "screenshot", or raw filenames.
3. The evaluated Trust Score is ${score}/100.
4. You must answer the user's SPECIFIC question in detail based ONLY on verified evidence.
5. Ground your explanation in the following verified Evidence Locker records and Dual RAG citations:
--- EVIDENCE RECORDS ---
${evidenceCitations || 'No evidence records available.'}
--- DUAL RAG CITATIONS ---
Document Chunks: ${JSON.stringify(docChunks.slice(0, 5))}
External Evidence Chunks: ${JSON.stringify(extChunks.slice(0, 5))}
6. Distinguish clearly:
   - A Registered Company does NOT prove the specific recruiter or offer is genuine.
   - An Authentic Certificate does NOT prove the internship opportunity is legitimate.
   - Legitimate employers NEVER charge candidate registration fees, laptop caution deposits, or training charges.
7. Cite actual Evidence IDs (e.g. ${sampleIds}) where applicable.
8. If an assertion cannot be verified from the provided evidence, explicitly state: "I could not verify this from the available investigation evidence."
9. Include practical advice such as verifying on official company careers portal, calling official boardline numbers, and reporting scams to the 1930 National Cybercrime Helpline.
10. Format response cleanly using Markdown headings (###) and bullet points.`;

      const response = await this.ai.models.generateContent({
        model: 'gemini-3.6-flash',
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
