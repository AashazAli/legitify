// ==============================================================================
// LEGITIFY TRANSPARENT RULE ENGINE
// Auditable rule execution with severity, evidence requirements, and score impacts
// ==============================================================================
import { RuleEvaluation, EvidenceItem, CertificateVerificationData } from '../../types';
import { CompanyData } from '../services/companyService';
import { DomainData } from '../services/domainService';
import { RecruiterData } from '../services/emailService';
import { DocumentExtractionResult } from '../services/documentService';
import { ThreatData } from '../services/threatService';

export interface RuleEngineContext {
  companyData?: CompanyData;
  domainData?: DomainData;
  recruiterData?: RecruiterData;
  documentData?: DocumentExtractionResult;
  certificateData?: CertificateVerificationData;
  threatData?: ThreatData;
  evidence: EvidenceItem[];
}

export function evaluateRules(ctx: RuleEngineContext): {
  rules: RuleEvaluation[];
  evidence: EvidenceItem[];
  scoreImpact: number;
} {
  const rules: RuleEvaluation[] = [];
  const generatedEvidence: EvidenceItem[] = [];
  let totalImpact = 0;

  // ----------------------------------------------------------------------------
  // R001: Recruiter domain alignment & free webmail check
  // ----------------------------------------------------------------------------
  if (ctx.recruiterData) {
    if (ctx.recruiterData.is_free_provider) {
      const isClaimingCorporate = ctx.companyData && ctx.companyData.status === 'ACTIVE';
      const r001: RuleEvaluation = {
        rule_id: "R001",
        name: "Public Webmail Used for Corporate Recruitment",
        description: "Recruiter uses a free public email provider (e.g. Gmail/Yahoo) while communicating on behalf of a registered company.",
        triggered: true,
        severity: isClaimingCorporate ? "HIGH" : "MEDIUM",
        score_impact: isClaimingCorporate ? -20 : -10,
        explanation: "Legitimate corporate recruiters typically communicate via verified corporate domain addresses rather than free public webmail accounts.",
        evidence_required: ["recruiter.email", "company.name"],
      };
      rules.push(r001);
      totalImpact += r001.score_impact;
    } else if (ctx.companyData?.domain && ctx.recruiterData.domain && ctx.recruiterData.domain !== ctx.companyData.domain) {
      const r001b: RuleEvaluation = {
        rule_id: "R001B",
        name: "Recruiter Domain Mismatch With Company",
        description: `Recruiter domain (${ctx.recruiterData.domain}) does not match official company domain (${ctx.companyData.domain}).`,
        triggered: true,
        severity: "HIGH",
        score_impact: -25,
        explanation: "The sender's domain is unaffiliated with the official corporate domain, indicating potential recruiter impersonation.",
        evidence_required: ["recruiter.domain", "company.domain"],
      };
      rules.push(r001b);
      totalImpact += r001b.score_impact;
    }
  }

  // ----------------------------------------------------------------------------
  // R002: Upfront payment & training fee demands
  // ----------------------------------------------------------------------------
  const hasThreatFee = ctx.threatData?.matches?.some(i => i.threat_type === 'FEE_FRAUD') ||
    (ctx.threatData as any)?.indicators?.some((i: any) => i.threat_type === 'FEE_FRAUD');
  if (ctx.documentData?.has_fee_demand || hasThreatFee) {
    const feeInfo = ctx.documentData?.requested_fees?.[0];
    const r002: RuleEvaluation = {
      rule_id: "R002",
      name: "Upfront Fee Demand in Recruitment Offer",
      description: "Document or message requests registration fees, security deposits, training costs, or equipment purchase before onboarding.",
      triggered: true,
      severity: "CRITICAL",
      score_impact: -50,
      explanation: "Legitimate companies and authorized internship providers do not require candidates to pay mandatory security deposits or training fees prior to joining.",
      evidence_required: ["document.text", "payment.keywords"],
    };
    rules.push(r002);
    totalImpact += r002.score_impact;

    generatedEvidence.push({
      category: "OFFER",
      evidence_type_category: "CONTRADICTORY_EVIDENCE",
      evidence_type: "UPFRONT_FEE_DEMAND",
      source_name: "Rule Engine (R002)",
      title: "Mandatory Upfront Fee Demand Detected",
      snippet: feeInfo ? `Reason: ${feeInfo.reason || 'Deposit'} | Amount: ${feeInfo.amount || 'Specified'} | Channel: ${feeInfo.channel || 'Direct'}` : 'Upfront fee language detected in offer text',
      evidence_text: "Clear violation of legitimate internship practices requiring upfront financial payment from candidate.",
      evidence_strength: "VERY_STRONG",
      status: "NEGATIVE",
      severity: "CRITICAL",
      verified: true,
      confidence: 98,
    });
  }

  // ----------------------------------------------------------------------------
  // R003: Newly registered domain with lookalike brand claims
  // ----------------------------------------------------------------------------
  if (ctx.domainData) {
    if (ctx.domainData.age_days && ctx.domainData.age_days < 60) {
      const r003: RuleEvaluation = {
        rule_id: "R003",
        name: "Newly Created Domain Entity",
        description: `Domain was registered recently (${ctx.domainData.age_days} days ago).`,
        triggered: true,
        severity: "HIGH",
        score_impact: -30,
        explanation: "Newly registered domains lack long-term operational track record and are frequently used in disposable recruitment scam campaigns.",
        evidence_required: ["domain.registration_date", "rdap.age"],
      };
      rules.push(r003);
      totalImpact += r003.score_impact;
    }

    if (ctx.domainData.lookalike_detected) {
      const r003b: RuleEvaluation = {
        rule_id: "R003B",
        name: "Typosquatting / Brand Lookalike Domain",
        description: `Domain '${ctx.domainData.domain}' appears to impersonate a known brand (${ctx.domainData.lookalike_target}).`,
        triggered: true,
        severity: "CRITICAL",
        score_impact: -45,
        explanation: "The domain uses deceptive spelling (homoglyphs/typosquatting) designed to mislead candidates into believing they are on the official brand portal.",
        evidence_required: ["domain.name", "brand.registry"],
      };
      rules.push(r003b);
      totalImpact += r003b.score_impact;
    }
  }

  // ----------------------------------------------------------------------------
  // R004: Certificate Verification Hierarchy
  // ----------------------------------------------------------------------------
  if (ctx.certificateData) {
    if (ctx.certificateData.status === "VERIFIED_AUTHENTIC") {
      const r004: RuleEvaluation = {
        rule_id: "R004",
        name: "Certificate Independently Authenticated",
        description: "Certificate verified through official issuer registry, valid ID syntax, and verified domain routing.",
        triggered: true,
        severity: "INFO",
        score_impact: +25,
        explanation: "Certificate credentials were confirmed against verified issuer conventions. Note: Certificate authenticity does not guarantee that related internship offers are legitimate.",
        evidence_required: ["certificate.id", "certificate.issuer", "verification.url"],
      };
      rules.push(r004);
      totalImpact += r004.score_impact;
    } else if (ctx.certificateData.status === "LIKELY_FRAUDULENT") {
      const r004b: RuleEvaluation = {
        rule_id: "R004B",
        name: "Deceptive Certificate Verification Endpoint",
        description: "Certificate points verification to a fraudulent, newly registered, or mismatched lookalike endpoint.",
        triggered: true,
        severity: "CRITICAL",
        score_impact: -45,
        explanation: "The certificate verification link intentionally routes to a third-party clone rather than the accredited institution.",
        evidence_required: ["certificate.verify_url", "issuer.domain"],
      };
      rules.push(r004b);
      totalImpact += r004b.score_impact;
    } else if (ctx.certificateData.status === "UNVERIFIED") {
      const r005: RuleEvaluation = {
        rule_id: "R005",
        name: "Certificate Unverified (Insufficient Independent Evidence)",
        description: "Certificate issuer or credentials cannot be validated automatically due to lack of public registry API.",
        triggered: true,
        severity: "INFO",
        score_impact: 0,
        explanation: "No independent cryptographic or public registry verification was available. The certificate is treated as UNVERIFIED, not fraudulent.",
        evidence_required: ["certificate.registry_api"],
      };
      rules.push(r005);
    }
  }

  // ----------------------------------------------------------------------------
  // R006: Decoupled Entity Correlation (Verified Company + Suspicious Recruiter)
  // ----------------------------------------------------------------------------
  if (
    ctx.companyData &&
    ctx.companyData.status === "ACTIVE" &&
    (ctx.recruiterData?.is_free_provider || ctx.domainData?.lookalike_detected || ctx.documentData?.has_fee_demand)
  ) {
    const r006: RuleEvaluation = {
      rule_id: "R006",
      name: "Impersonation Risk (Legitimate Brand Targeted)",
      description: "Company entity is verified legitimate, but communication channels (email/domain/offer) show anomalies.",
      triggered: true,
      severity: "HIGH",
      score_impact: -15,
      explanation: "Scammers frequently exploit the reputation of reputable, registered companies to create deceptive job offers.",
      evidence_required: ["company.registry", "recruiter.email", "domain.dns"],
    };
    rules.push(r006);
    totalImpact += r006.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R007: Threat IOC Registry Match
  // ----------------------------------------------------------------------------
  const verifiedThreats = ctx.threatData?.matches?.filter(m => m.source !== "Heuristic Pattern Engine") || [];
  const threatCount = verifiedThreats.length;
  if (threatCount > 0 || ctx.threatData?.known_threat) {
    const r007: RuleEvaluation = {
      rule_id: "R007",
      name: "Active Threat Intelligence Match",
      description: `Matched ${threatCount || 1} known scam or malicious IOCs in intelligence database.`,
      triggered: true,
      severity: "CRITICAL",
      score_impact: -40,
      explanation: "Target entity matches existing entries in fraud databases or security blacklists.",
      evidence_required: ["threat_indicators.lookup"],
    };
    rules.push(r007);
    totalImpact += r007.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R008: High-Pressure Urgency Tactics (InternShield parity)
  // ----------------------------------------------------------------------------
  if (ctx.documentData?.has_urgency) {
    const r008: RuleEvaluation = {
      rule_id: "R008",
      name: "High-Pressure Acceptance Deadline / Artificial Urgency",
      description: "Document or message enforces artificial urgency (e.g. 24-72 hours deadline) to force hasty candidate response.",
      triggered: true,
      severity: "HIGH",
      score_impact: -20,
      explanation: "Scam campaigns enforce urgent response deadlines to bypass due diligence and extract upfront fees.",
      evidence_required: ["document.urgency_phrases"],
    };
    rules.push(r008);
    totalImpact += r008.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R009: Informal / Unprofessional Communication Channels (InternShield parity)
  // ----------------------------------------------------------------------------
  if (ctx.documentData?.has_informal_channel) {
    const r009: RuleEvaluation = {
      rule_id: "R009",
      name: "Informal / Unencrypted Channel for Official Hiring",
      description: "Recruitment process is routed exclusively through WhatsApp, Telegram, or Google Forms.",
      triggered: true,
      severity: "HIGH",
      score_impact: -25,
      explanation: "Legitimate corporate recruiters conduct hiring via official enterprise systems, not private messaging platforms.",
      evidence_required: ["document.channels"],
    };
    rules.push(r009);
    totalImpact += r009.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R010: Severe Letterhead & Formatting Flaws (InternShield parity)
  // ----------------------------------------------------------------------------
  if (ctx.documentData?.has_grammar_anomalies) {
    const r010: RuleEvaluation = {
      rule_id: "R010",
      name: "Structural & Typographical Letterhead Flaws",
      description: "Offer letter contains glaring grammatical errors, syntax flaws, or contradictory job designations.",
      triggered: true,
      severity: "HIGH",
      score_impact: -15,
      explanation: "Official corporate documents undergo strict legal and brand review. Severe flaws indicate a fabricated template.",
      evidence_required: ["document.syntax_anomalies"],
    };
    rules.push(r010);
    totalImpact += r010.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R011: Implausible Compensation / Bait Stipend (InternShield parity)
  // ----------------------------------------------------------------------------
  if (ctx.documentData?.has_implausible_stipend) {
    const r011: RuleEvaluation = {
      rule_id: "R011",
      name: "Implausible Compensation Anomaly",
      description: "Stipend or compensation claims significantly exceed standard industry benchmarks for introductory roles.",
      triggered: true,
      severity: "MEDIUM",
      score_impact: -15,
      explanation: "Unrealistically high stipends for basic entry internships are commonly used to attract candidates before requesting onboarding fees.",
      evidence_required: ["document.stipend"],
    };
    rules.push(r011);
    totalImpact += r011.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R012: Generic Impersonal Greeting (InternShield parity)
  // ----------------------------------------------------------------------------
  if (ctx.documentData?.has_generic_greeting) {
    const r012: RuleEvaluation = {
      rule_id: "R012",
      name: "Impersonal / Generic Candidate Greeting",
      description: "Offer letter uses generic greeting ('Dear Candidate/Student') instead of personalized applicant name.",
      triggered: true,
      severity: "MEDIUM",
      score_impact: -10,
      explanation: "Official employment confirmation letters are issued to specific individuals, not generic placeholders.",
      evidence_required: ["document.greeting"],
    };
    rules.push(r012);
    totalImpact += r012.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R013: Direct Selection Without Interview / Assessment Rounds
  // ----------------------------------------------------------------------------
  if ((ctx.documentData as any)?.has_direct_selection) {
    const r013: RuleEvaluation = {
      rule_id: "R013",
      name: "Direct Appointment Without Technical / HR Assessment Rounds",
      description: "Offer claims direct selection without interviews, tests, or screening rounds.",
      triggered: true,
      severity: "HIGH",
      score_impact: -30,
      explanation: "Legitimate enterprise employers and accredited internship programs mandate structured interviews and skill assessments before issuing offers. Direct selection is a high-risk hallmark of recruitment fee fraud.",
      evidence_required: ["document.direct_selection_clauses"],
    };
    rules.push(r013);
    totalImpact += r013.score_impact;
  }

  // ----------------------------------------------------------------------------
  // R014: Conflicting Multi-Company Spoofing / Entity Contradiction
  // ----------------------------------------------------------------------------
  if ((ctx.documentData as any)?.has_multi_company_spoofing) {
    const r014: RuleEvaluation = {
      rule_id: "R014",
      name: "Multiple Disparate Corporate Entities Spoofed on Single Letterhead",
      description: "Document references multiple unrelated enterprise brands or conflicting statutory bodies simultaneously.",
      triggered: true,
      severity: "CRITICAL",
      score_impact: -35,
      explanation: "Unrelated corporate identities or joint public-private co-branding on offer documents indicates fraudulent fabrication designed to exploit multiple brand reputations.",
      evidence_required: ["document.company_entities"],
    };
    rules.push(r014);
    totalImpact += r014.score_impact;
  }

  return {
    rules,
    evidence: generatedEvidence,
    scoreImpact: totalImpact,
  };
}

