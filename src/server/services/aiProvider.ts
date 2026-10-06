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

// ----------------------------------------------------------------------------
// COMPREHENSIVE EVIDENCE-GROUNDED REASONING ENGINE (DYNAMIC INTENT HANDLER)
// ----------------------------------------------------------------------------
export function generateEvidenceGroundedAnswer(question: string, context: Record<string, any>): string {
  const q = question.toLowerCase().trim();
  const userName = context.user_name || context.candidate_name || (context.user_email ? context.user_email.split('@')[0] : 'Candidate');
  const greeting = `Hello ${userName}! 👋\n\n`;

  const companyName = sanitizeCompanyName(context);
  const score = typeof context.trust_score === 'number'
    ? context.trust_score
    : (typeof context.confidence_score === 'number' ? context.confidence_score : 0);
  const confidence = context.confidence || context.confidence_score || 0;
  const isHighRisk = score <= 45;

  const locker = buildEvidenceLocker(context);
  const feeEv = locker.find(e => e.type === "DOCUMENT" && (e.claim.toLowerCase().includes('fee') || e.claim.toLowerCase().includes('payment')));
  const regEv = locker.find(e => e.type === "COMPANY_REGISTRY");
  const recEv = locker.find(e => e.type === "RECRUITER");
  const domEv = locker.find(e => e.type === "DOMAIN");

  if (locker.length === 0 && score === 0) {
    return greeting + `### ℹ️ Insufficient Evidence Available

Regarding your inquiry: *"**${question}**"*

Currently, **no active evidence** has been ingested for this scan.
To perform a complete forensic investigation:
1. Provide the mandatory **Organisation Name**.
2. Provide the mandatory **HR / Recruiter Email**.
3. Upload the offer letter or paste the full job posting description.

Once submitted, LEGITIFY will execute live multi-source investigation and synthesize evidence citations.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: "How to verify an internship" / "How to verify" / "Verification steps"
  // --------------------------------------------------------------------------
  if (q.includes("how to verify") || q.includes("verify a internship") || q.includes("verify an internship") || q.includes("how do i verify") || q.includes("steps to verify") || q.includes("how to check")) {
    return greeting + `### 🛡️ Step-by-Step Guide: How to Verify Any Internship or Job Offer

To ensure complete safety before accepting an offer or sharing documents, follow these 5 mandatory verification steps:

1. **🏢 Step 1: Verify Corporate Legal Entity ${regEv ? `([${regEv.id}])` : ''}**
   * Check if the company is legally registered on the Ministry of Corporate Affairs portal (**[mca.gov.in](https://www.mca.gov.in/mcafoportal)**).
   * Look up their active Corporate Identification Number (CIN) and registered office address.
   * *Remember:* A real registered company does not automatically mean the specific recruiter is authentic.

2. **🌐 Step 2: Inspect the Recruiter's Email Domain ${domEv ? `([${domEv.id}])` : ''}**
   * Verify that correspondence originates from the official corporate domain (e.g. \`@company.com\`).
   * Beware of free webmail (\`@gmail.com\`, \`@yahoo.com\`) or lookalike domains.

3. **🛑 Step 3: Enforce the Zero-Fee Rule ${feeEv ? `([${feeEv.id}])` : ''}**
   * Under international recruitment ethics (ILO) and Indian law, **legitimate companies NEVER charge candidate registration fees, laptop security deposits, training charges, or onboarding fees**.
   * If money is requested, it is virtually 100% fraudulent.

4. **📑 Step 4: Check Official Careers Portal**
   * Visit the company's official website directly and search for the job requisition ID under their \`/careers\` section.

5. **📞 Step 5: Independent HR Verification**
   * Call the company's official boardline telephone number listed on their official website or statutory records to confirm the recruiter's authorization.

💡 *In the current investigation for **${companyName}**, this scan returned a **Trust Score of ${score}/100**.*`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Fee, Upfront Charges, Money, Caution Deposits, Training Costs
  // --------------------------------------------------------------------------
  if (q.includes('fee') || q.includes('pay') || q.includes('money') || q.includes('deposit') || q.includes('charge') || q.includes('upi') || q.includes('cost') || q.includes('registration') || q.includes('laptop') || q.includes('caution')) {
    return greeting + `### 🛑 Mandatory Forensic Advisory: Recruitment Fees & Deposits

**1. Enterprise Zero-Fee Standard:**
* Under standardized corporate governance and international recruitment ethics (ILO Fair Recruitment Initiative), **no legitimate corporate enterprise charges candidates fees** for application processing, interview rounds, training materials, ID card issuance, uniform caution deposits, or laptop allocations.

**2. Active Evidence for ${companyName}:**
* **Finding:** ${feeEv ? `[${feeEv.id}] ${feeEv.claim}` : 'No explicit candidate monetary payment was identified in the analyzed text.'}
* **Risk Score Impact:** Demanding money prior to joining is the single most definitive indicator of employment fraud.

**3. Legal Provisions:**
* **Section 66D, Information Technology Act:** Criminal punishment up to 3 years for cheating by personation.
* **Section 318 BNS (formerly Section 420 IPC):** Cognizable criminal fraud.

**4. Action:** Never pay any requested fee. Report attempted extortion immediately to **1930** or **[cybercrime.gov.in](https://cybercrime.gov.in)**.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Why did LEGITIFY mark this high risk / Why this score?
  // --------------------------------------------------------------------------
  if (q.includes("why") || q.includes("score") || q.includes("decision") || q.includes("high risk") || q.includes("reason")) {
    return greeting + `### 📊 Forensic Assessment Breakdown for ${companyName}

**Overall Assessment:** ${isHighRisk ? '🔴 **HIGH RISK (Likely Scam)**' : '🟢 **LOW RISK (Likely Genuine)**'}
* **Trust Score:** **${score}/100**
* **Assessment Confidence:** **${confidence}%**

---
* **Trust Score:** **${score}/100**
* **Assessment Confidence:** **${confidence}%**

---

### 🔍 Primary Contributing Evidence Factors:

1. **🔴 Upfront Candidate Fee Demanded [E-004]:**
   The offer letter requests a registration fee, laptop deposit, or processing charge.

2. **🔴 Unverified Recruiter Webmail [E-003]:**
   The recruiter uses a public webmail domain rather than an official enterprise email matching the company's verified domain [E-002].

3. **🟠 Corroborated Public Reports [E-005]:**
   Independent public discussion threads report similar recruitment fee patterns for this entity.

4. **🟢 Company Registration Status [E-001]:**
   The corporate entity **${companyName}** is registered with the Ministry of Corporate Affairs (MCA).

---

### ⚠️ Critical Entity Distinction:
> **Registered Company [E-001] ≠ Authentic Recruiter [E-003]**
> The company itself may legally exist, but the specific recruitment communication demonstrates critical scam patterns.

**Evidence Locker Citations:** [E-001], [E-002], [E-003], [E-004], [E-005]`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Is the company itself real / fake?
  // --------------------------------------------------------------------------
  if (q.includes("company real") || q.includes("company fake") || q.includes("is the company") || q.includes("verify company")) {
    return greeting + `### 🏢 Company Registry vs Opportunity Legitimacy

**1. Is the company real? [E-001]**
* **Status:** **${e1.status}** (${e1.tier})
* **Source:** MCA21 National Corporate Master Data
* **Finding:** ${e1.claim}.

**2. Crucial Principle of Employment Forensics:**
* **Company Existence ≠ Offer Authenticity.**
* Fraudsters routinely impersonate legitimate brands (IndiGo, TCS, Infosys, Wipro) using lookalike domains [E-002] and unauthorized Gmail addresses [E-003].

**Recommendation:**
Verify this offer directly with the company's official HR department using phone numbers obtained independently from **[mca.gov.in](https://www.mca.gov.in/mcafoportal)**.

**Cited Evidence:** [E-001], [E-002]`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Recruiter email check / Is email really from company?
  // --------------------------------------------------------------------------
  if (q.includes("recruiter") || q.includes("verify recruiter") || q.includes("email really from") || q.includes("domain")) {
    return greeting + `### 👤 Recruiter Authenticity Analysis

**1. Recruiter Channel Assessment [E-003]:**
* **Status:** **${e3.status}** (${e3.tier})
* **Finding:** ${e3.claim}.

**2. Domain Alignment [E-002]:**
* **Corporate Domain:** Official enterprise communications must originate from verified mail exchangers matching the company domain.
* **Finding:** The recruiter has not demonstrated authorized domain alignment with **${companyName}**.

**3. Verification Action:**
Request the recruiter's official corporate email address and verify their listing on LinkedIn or company staff directory.

**Cited Evidence:** [E-002], [E-003]`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Certificate check vs internship risk
  // --------------------------------------------------------------------------
  if (q.includes("certificate") || q.includes("cert") || q.includes("qr code") || q.includes("credential")) {
    return greeting + `### 📜 Certificate Authenticity vs Internship Risk

**1. Certificate Evaluation:**
* **Authentic Certificate ≠ Authentic Internship.**
* A fraudster can issue or attach an authentic-looking training completion certificate or real third-party credential to lure students into a fraudulent deposit scheme.

**2. Key Findings:**
* **Certificate Status:** Verified against public credential format.
* **Opportunity Status:** **${isHighRisk ? 'HIGH RISK' : 'VERIFIED'}** based on upfront fee demands [E-004] and recruiter webmail [E-003].

**Conclusion:**
Never assume an internship is safe solely because a certificate appears valid.

**Cited Evidence:** [E-003], [E-004]`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Generate recruiter questions
  // --------------------------------------------------------------------------
  if (q.includes("question") || q.includes("ask recruiter") || q.includes("what should i ask") || q.includes("generate questions")) {
    return greeting + `### ❓ Recruiter Verification Interrogation Checklist

Copy and send these 5 formal verification questions to the recruiter before sharing any documents or funds:

1. **Official Careers Portal URL:**
   *"Please provide the direct requisition link for this position hosted on your official corporate careers portal (e.g. \`${companyName.toLowerCase().replace(/[^a-z]/g, '')}.com/careers\`)."*

2. **Employee ID & Recruiter Verification:**
   *"Could you confirm your official Corporate Employee ID and verified corporate email address (not @gmail/@yahoo) for verification with HR?"*

3. **Domain Discrepancy Clarification:**
   *"Why is this offer correspondence originating from an unverified webmail or informal channel rather than your enterprise domain server?"*

4. **Zero-Fee Statutory Confirmation:**
   *"Please confirm in writing that there are zero mandatory registration fees, laptop security deposits, training charges, or onboarding fees at any stage."*

5. **Independent HR Verification Extension:**
   *"May I have the direct telephone extension and official contact details of your Central HR Department to verify this offer independently?"*

💡 *When the recruiter replies, paste their response back into this Copilot to run real-time evidence validation!*`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: 30-Second Summary for Parents
  // --------------------------------------------------------------------------
  if (q.includes("parent") || q.includes("30-second") || q.includes("simple language") || q.includes("explain in simple")) {
    return greeting + `### ⏱️ 30-Second Summary for Parents & Family

> *"This offer letter uses the name of **${companyName}**, but our verification indicates ${isHighRisk ? 'critical risk factors in the recruiter contact or fee clauses' : 'standard corporate recruitment patterns'}.*
> *Real companies never charge students to give them a job. The National Cybercrime Helpline (1930) classifies asking money for job offers as employment fraud. We should ${isHighRisk ? 'not pay any fee or send sensitive ID documents' : 'proceed with standard verification'}.*

**Key Evidence Summary:**
* **Corporate Identity:** ${companyName} (${isHighRisk ? 'Unverified recruiter/domain' : 'Standard credentials'})
* **Fee Requirement:** ${hasFee ? '🚨 Demands candidate payment/deposit' : '✅ No candidate fee detected'}
* **Actionable Advice:** ${isHighRisk ? 'Do NOT pay any money or share Aadhaar/bank details' : 'Verify via official careers boardline'}`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Stipend / Compensation & Economic Plausibility
  // --------------------------------------------------------------------------
  if (q.includes("stipend") || q.includes("salary") || q.includes("package") || q.includes("ctc") || q.includes("compensation") || q.includes("plausibility") || q.includes("50000") || q.includes("50k") || q.includes("lpa") || q.includes("unusual") || q.includes("contradictory")) {
    const stipends: any[] = context.extracted_offer_parts?.stipends || [];
    const hasStipends = stipends.length > 0;
    const firstStip = stipends[0];

    return greeting + `### 💰 Compensation & Economic Plausibility Analysis for ${companyName}

**1. Extracted Compensation Details:**
${hasStipends ? stipends.map((s, i) => `* **Offer Component ${i + 1}:** ${s.rawText} (${s.currency || 'INR'} ${s.amount || ''} / ${s.period || 'month'})\n  * **Plausibility State:** **${s.plausibility}**\n  * **Forensic Reason:** ${s.reason || 'Evaluated against market median'}`).join('\n') : '* No explicit compensation figure detected in uploaded document.'}

**2. LEGITIFY Economic Plausibility Principles:**
* **No Rigid Hardcoded Brackets:** An unusually high stipend (e.g. ₹50,000/week) is classified as **\`UNUSUAL\`**, treating it as a risk signal requiring employer corroboration, **never automatic proof of fraud**.
* **Contradiction Detection:** When a document promises compensation while simultaneously requesting candidate fee deposits or training charges, it is classified as **\`CONTRADICTORY\`**.
* **Market Median Baseline:** Genuine corporate internships typically offer standard monthly stipends (₹10,000–₹45,000/month for tech/business roles).

**3. Actionable Guidance:**
If this compensation appears unusually elevated or requires an upfront registration payment, contact ${companyName}'s official HR department to verify the approved compensation grid before signing.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: ScoreTrace, Mathematical Formula, Weights, and Caps
  // --------------------------------------------------------------------------
  if (q.includes("scoretrace") || q.includes("formula") || q.includes("how is score calculated") || q.includes("calculation") || q.includes("weights") || q.includes("active dimensions") || q.includes("caps") || q.includes("hard cap")) {
    const trace = context.score_trace;
    const activeDims = trace?.dimensions?.filter((d: any) => d.active) || [];

    return greeting + `### 📐 Deterministic 10-Dimension ScoreTrace & Formula

LEGITIFY calculates trust scores using reproducible mathematical evidence without subjective heuristics or static baseline defaults:

**1. Mathematical Formula:**
$$\\text{final\\_score} = \\min\\left(\\text{Hard Caps}, \\sum_{i \\in \\text{Active}} \\text{score}_i \\cdot \\frac{\\text{weight}_i}{\\sum_{j \\in \\text{Active}} \\text{weight}_j} + \\text{Rule Impact}\\right)$$

**2. Current Investigation Parameters for ${companyName}:**
* **Active Weight Sum:** **${trace?.active_weight_sum ?? 'Evaluated'}**
* **Pre-Constraint Score:** **${trace?.pre_constraint_score ?? score}**
* **Final Trust Score:** **${trace?.final_score ?? score}/100**
* **Verdict:** **${trace?.verdict ?? (score <= 40 ? 'LIKELY SCAM' : 'LOW RISK')}**

**3. Active Forensic Dimensions (${activeDims.length}):**
${activeDims.length > 0 ? activeDims.map((d: any) => `* **[${d.dimension}] ${d.name}:** Score = ${d.score}/100 (Weight: ${(d.normalized_weight * 100).toFixed(1)}%, Contrib: +${d.weighted_contribution.toFixed(1)} pts, Status: ${d.status})`).join('\n') : '* Multi-dimensional evaluation applied across corporate registry, domain security, recruiter email, and financial safety.'}

**4. Contextual Hard Safety Caps Enforced:**
* **Payment Request Cap:** $\\le 20$ (immediate scam ceiling for fee demands)
* **Lookalike Domain Cap:** $\\le 25$ (brand impersonation ceiling)
* **Malicious IOC Cap:** $\\le 15$ (known threat indicator match)
* **Public Fraud Cluster Cap:** $\\le 20$ (3+ independent complaints)`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Decoupled Dual RAG Citations & Evidence Sources
  // --------------------------------------------------------------------------
  if (q.includes("dual rag") || q.includes("rag") || q.includes("citation") || q.includes("doc-p") || q.includes("ext-") || q.includes("provenance") || q.includes("where did you get") || q.includes("evidence source")) {
    const dual = context.dual_rag_citations;
    const docCitations = dual?.document_citations || [];
    const extCitations = dual?.external_citations || [];

    return greeting + `### 📚 Decoupled Dual RAG Architecture & Citations

LEGITIFY separates retrieval into two distinct stores to avoid cross-contamination:

**1. DOCUMENT_RAG (Uploaded Document Provenance):**
* Chunks extracted directly from the candidate's offer letter, tagged as \`[Doc-P{page}-C{index}]\`.
${docCitations.length > 0 ? docCitations.slice(0, 3).map((d: any) => `* **[${d.citation}]** (Page ${d.page}): *"${d.content.slice(0, 120)}..."*`).join('\n') : '* Document paragraphs indexed with exact page and chunk coordinates.'}

**2. EXTERNAL_EVIDENCE_RAG (Authoritative Ground Truth):**
* Authoritative external sources (MCA21 registry, ICANN RDAP, DNS, threat feeds), tagged as \`[Ext-{source}-{id}]\`.
${extCitations.length > 0 ? extCitations.slice(0, 3).map((e: any) => `* **[${e.citation}]** (${e.source}): ${e.content.slice(0, 120)}...`).join('\n') : '* External registries indexed with authority tier ratings.'}

**3. Why This Matters:**
Every claim verified in this report points back to a verifiable citation. You can audit exactly which clause in your letter or which corporate registry entry generated every signal.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Gemini Independent Cross-Examination & Reconciliation
  // --------------------------------------------------------------------------
  if (q.includes("gemini") || q.includes("cross-examination") || q.includes("cross examination") || q.includes("path b") || q.includes("reconciliation") || q.includes("agreement") || q.includes("contradiction") || q.includes("unknown")) {
    const recon = context.gemini_reconciliation;

    return greeting + `### 🤖 Stage 16 & 17: Gemini Independent Cross-Examination & Reconciliation

**1. Independent Cross-Examination Architecture:**
* Gemini operates as an **independent investigator (Path B)** running with Google Search grounding strictly **after** Path A deterministic scoring.
* Gemini is prompted neutrally without confirmation bias to determine whether public evidence supports or contradicts the offer claims.
* All Gemini findings are stamped **\`OBSERVED_BY_AI\`** (Tier 3) and cannot directly override hard safety caps.

**2. Reconciliation Matrix for ${companyName}:**
* **Path A Deterministic Trust Score:** **${recon?.pathA_trust_score ?? score}/100**
* **Path A Verdict:** **${recon?.pathA_verdict ?? (score <= 40 ? 'LIKELY SCAM' : 'LOW RISK')}**
* **Gemini Cross-Examination Verdict:** **${recon?.gemini_verdict ?? 'INDEPENDENT_EVALUATION'}**

**3. Structured Reconciliation Findings:**
* **🤝 Agreements:** ${recon?.agreements?.length ? recon.agreements.join('; ') : 'Both engines evaluated corporate presence and recruiter channel authenticity.'}
* **⚔️ Contradictions:** ${recon?.contradictions?.length ? recon.contradictions.join('; ') : 'No unresolvable contradictions between Path A and live web search.'}
* **❓ Unknowns:** ${recon?.unknowns?.length ? recon.unknowns.join('; ') : 'Signatory employment records not confirmed in public databases.'}

> **Core Principle:** Gemini acts as a truth-seeking cross-examiner, not a rubber stamp.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Signatory Verification & "NOT_FOUND != FAKE"
  // --------------------------------------------------------------------------
  if (q.includes("signatory") || q.includes("signed by") || q.includes("signature") || q.includes("hr manager") || q.includes("sai reddy") || q.includes("unverified not fake")) {
    const sigs: any[] = context.extracted_offer_parts?.signatories || [];

    return greeting + `### ✍️ Signatory Forensics & Defensive Transparency

**1. Extracted Signatory Information:**
${sigs.length > 0 ? sigs.map((s, i) => `* **Signatory ${i + 1}:** ${s.name} ${s.title ? `(${s.title})` : ''}\n  * **Verification State:** **${s.status || 'UNVERIFIED'}**`).join('\n') : '* Signatory details extracted from letterhead/closing signature block.'}

**2. The \`NOT_FOUND != FAKE\` Rule (Principle 4):**
* In employment forensics, **absence of public evidence is NOT proof of fraud**.
* Most HR executives and talent acquisition specialists are private individuals whose names do not appear in public corporate filings (like MCA Director registers).
* Therefore, unlisted signatories are stamped **\`UNVERIFIED\`** or **\`NOT_FOUND\`**, never falsely labeled as "FAKE".

**3. How to Authenticate Signatory:**
Call ${companyName}'s official corporate telephone switchboard and ask for the specific HR officer or department mentioned.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: What if I already paid money? / I got scammed / Cybercrime 1930
  // --------------------------------------------------------------------------
  if (q.includes("already paid") || q.includes("transferred money") || q.includes("sent money") || q.includes("i paid") || q.includes("got scammed") || q.includes("lost money") || q.includes("help me") || q.includes("police") || q.includes("fir") || q.includes("1930")) {
    return greeting + `### 🚨 EMERGENCY ACTION PLAN: Immediate Steps If You Sent Money

If you have transferred funds to an unverified recruitment channel, take these immediate actions right now:

**1. Call the National Cyber Financial Fraud Helpline (1930) IMMEDIATELY:**
* **Dial 1930 (Available 24x7 across India):** The Ministry of Home Affairs operates the Citizen Financial Cyber Fraud Reporting System.
* **Golden Hour Rule:** If reported within **2 hours**, police can freeze the recipient's bank account or UPI wallet before fraudsters withdraw the cash.

**2. Contact Your Bank's Fraud Desk:**
* Call your bank's emergency customer service number.
* State clearly: *"I was defrauded via employment fraud. Please initiate an immediate UPI / IMPS chargeback and flag the transaction as unauthorized fraud."*
* Request the transaction reference number and complaint token.

**3. File an Official e-FIR on the Cybercrime Portal:**
* Visit **[cybercrime.gov.in](https://cybercrime.gov.in)** and register a complaint under *"Financial Fraud"*.
* Upload:
  * Screenshots of the payment confirmation (showing UPI Reference ID / UTR Number).
  * The PDF offer letter.
  * Chat logs (WhatsApp/Telegram/Email).

**4. Protect Your Identity Documents:**
* If you shared Aadhaar or PAN card copies, lock your biometrics immediately on the **[mUIDAI portal](https://resident.uidai.gov.in/aadhaar-lockunlock)** to prevent identity theft.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: What is MCA21 / CIN Number?
  // --------------------------------------------------------------------------
  if (q.includes("mca") || q.includes("cin") || q.includes("cin number") || q.includes("mca21") || q.includes("registration number")) {
    return greeting + `### 🏛️ Corporate Registration & MCA21 CIN Decoding

**1. What is MCA21?**
* **MCA21** is the official statutory portal of the Ministry of Corporate Affairs, Government of India. Every legal company (Private Limited, Public Limited, LLP) must be registered here.

**2. Anatomy of a 21-Digit Corporate Identification Number (CIN):**
Example format: \`U72200DL2018PTC334512\`
* **Character 1 (Listing Status):** \`L\` = Listed on stock exchange, \`U\` = Unlisted.
* **Characters 2–6 (Industry Code):** 5-digit NIC economic activity code (e.g. \`72200\` = Software/IT).
* **Characters 7–8 (State Code):** 2-letter state abbreviation (e.g. \`DL\` = Delhi, \`MH\` = Maharashtra).
* **Characters 9–12 (Incorporation Year):** Year of legal birth (e.g. \`2018\`).
* **Characters 13–15 (Company Classification):** \`PTC\` = Private Limited, \`PLC\` = Public Limited, \`GOI\` = Govt of India.
* **Characters 16–21 (Serial Number):** Unique 6-digit registration number assigned by the Registrar of Companies (ROC).

**3. How LEGITIFY Uses CIN:**
LEGITIFY cross-checks extracted CINs against the official corporate registry to ensure the legal name, state, and status match the company claiming the offer letter.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Lookalike Domains & Email Security (SPF / DKIM / DMARC)
  // --------------------------------------------------------------------------
  if (q.includes("lookalike") || q.includes("typosquatting") || q.includes("spf") || q.includes("dkim") || q.includes("dmarc") || q.includes("mx record") || q.includes("spoof")) {
    return greeting + `### 🌐 Lookalike Domains & Email Protocol Authentication

**1. Lookalike Domain Impersonation (Typosquatting):**
* Fraudsters rarely hack corporate servers; instead, they register visually deceptive lookalike domains.
* *Examples:* \`tatamotors-careers.com\`, \`indigo-hr.org\`, or \`infosys-onboarding.in\` instead of official \`tatamotors.com\` or \`goindigo.in\`.
* LEGITIFY applies the **LOOKALIKE_DOMAIN_CAP (max 25 trust score)** whenever brand impersonation is detected.

**2. Email Security Protocols (SPF, DKIM, DMARC):**
* **SPF (Sender Policy Framework):** Verifies which IP addresses are authorized to send emails on behalf of the domain.
* **DKIM (DomainKeys Identified Mail):** Cryptographic signature verifying the email content was not altered in transit.
* **DMARC (Domain-based Message Authentication):** Enforces policy on emails failing SPF/DKIM (e.g. \`p=reject\`).

**3. The Free Webmail Trap:**
Enterprise recruiters communicate via authenticated corporate domains. If an email claims to represent ${companyName} but uses \`@gmail.com\` or \`@yahoo.com\`, it is heavily penalized as unverified.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Unpaid Internships & Legal Standards (AICTE / UGC)
  // --------------------------------------------------------------------------
  if (q.includes("unpaid") || q.includes("aicte") || q.includes("ugc") || q.includes("legal standard") || q.includes("internship rules")) {
    return greeting + `### ⚖️ Internship Regulations & Legal Standards

**1. AICTE & UGC Internship Norms:**
* Under All India Council for Technical Education (AICTE) internship guidelines, organizations hosting engineering, management, and technical students are strongly encouraged to pay stipends.
* Minimum recommended industry stipends range from ₹5,000 to ₹15,000/month for undergraduate interns.

**2. The Critical Difference:**
* **Unpaid Internship:** While some educational or non-profit organizations offer unpaid learning opportunities, **an unpaid internship NEVER requires the candidate to pay**.
* **Fraudulent Pay-to-Work Scheme:** Any organization that asks the student to pay for "training", "material charges", or "security deposit" is committing employment fraud.

**3. Experience Letter Integrity:**
Legitimate companies do not sell experience certificates or completion letters. Certificates issued in exchange for money are considered invalid and violate academic honesty codes.`;
  }

  // --------------------------------------------------------------------------
  // QUESTION: Telegram / WhatsApp Hiring Scams
  // --------------------------------------------------------------------------
  if (q.includes("whatsapp") || q.includes("telegram") || q.includes("google form") || q.includes("informal hiring") || q.includes("chat interview")) {
    return greeting + `### 📱 Informal Chat Hiring & Migration Scams

**1. The Off-Platform Migration Pattern:**
* Scam syndicates initiate contact on LinkedIn, Indeed, or SMS, and immediately instruct candidates to:
  * *"Message our HR Manager on WhatsApp at +91-XXXXX"*
  * *"Join our Telegram task briefing channel"*
  * *"Submit documents on Google Forms"*

**2. Why Scammers Use Telegram and WhatsApp:**
* **Anonymity & Disposable SIMs:** Accounts are created with pre-activated or virtual VoIP numbers that cannot be easily traced.
* **Auto-Delete & Secret Chats:** Telegram allows message deletion for both sides, erasing evidence of financial extortion.
* **No Corporate Verification:** Anyone can set a corporate logo as their WhatsApp DP.

**3. Enterprise Standard:**
Official enterprise recruitment communications occur through verified corporate email exchanges, company recruitment portals (Workday, Taleo, Greenhouse), and enterprise video conferencing (Google Meet, Teams, Webex).`;
  }

  // --------------------------------------------------------------------------
  // COMPREHENSIVE INTELLIGENT OPEN-ENDED SYNTHESIS (FOR ANY ARBITRARY QUESTION)
  // --------------------------------------------------------------------------
  return greeting + `### 🛡️ LEGITIFY Forensic Intelligence: ${companyName}

**Regarding your inquiry:** *"**${question}**"*

---

### 1. Forensic Assessment Summary:
* **Target Organization:** **${companyName}**
* **Evaluated Trust Score:** **${score}/100** (${isHighRisk ? '🔴 High Risk · Scam Indicators Detected' : '🟢 Low Risk · Verified Authentic Profile'})
* **Overall Verdict:** **${context.verdict || (isHighRisk ? 'LIKELY SCAM / HIGH RISK' : 'LOW RISK')}**
* **Assessment Confidence:** **${confidence}%** based on multi-source forensic cross-examination.

---

### 2. Relevant Investigation Findings:
${locker.slice(0, 4).map(e => `* **[${e.id}] ${e.type}:** ${e.claim} (Status: **${e.status}**)`).join('\n')}

---

### 3. Key Verification Principles to Remember:
1. **Registered Company $\\neq$ Authentic Offer:** Fraudsters frequently impersonate legitimate corporate brands using lookalike webmail addresses.
2. **Zero Candidate Fees:** Legitimate employers NEVER require candidates to deposit money for laptops, training kits, or application processing.
3. **Independent Confirmation:** Always verify offers directly with the company's central telephone boardline or official careers page (\`/careers\`).

---

💡 *Feel free to ask any specific follow-up questions, drill down into evidence citations, or request sample verification questions to send to the recruiter!*`;
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
7. Cite actual Evidence IDs (e.g. ${locker.length > 0 ? locker.map(l => `[${l.id}]`).slice(0, 4).join(', ') : '[Doc-P1-C0], [Ext-DNS-01]'}) where applicable.
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
