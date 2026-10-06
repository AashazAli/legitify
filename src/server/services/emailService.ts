// ==============================================================================
// RECRUITER & EMAIL AUTHENTICITY SERVICE
// ==============================================================================
import { normalizeEmail, extractDomainFromEmail, isFreeEmailProvider } from '../utils/normalizer';
import { EvidenceItem } from '../../types';

export type RecruiterData = RecruiterAnalysisData;
export interface RecruiterAnalysisData {
  email: string;
  normalized_email: string;
  sender_domain: string;
  company_domain?: string;
  domain_alignment: "EXACT_MATCH" | "SUBSIDIARY_MATCH" | "FREE_EMAIL" | "MISMATCH" | "LOOKALIKE" | "UNKNOWN" | "MATCH";
  free_email_provider: boolean;
  is_free_provider?: boolean;
  domain?: string;
  display_name?: string;
  spf_status?: "PASS" | "FAIL" | "NEUTRAL" | "UNAVAILABLE";
  dkim_status?: "PASS" | "FAIL" | "NEUTRAL" | "UNAVAILABLE";
  dmarc_status?: "PASS" | "FAIL" | "NEUTRAL" | "UNAVAILABLE";
  known_threat: boolean;
}

export function analyzeRecruiterEmail(
  emailInput: string,
  claimedCompanyDomain?: string,
  claimedCompanyName?: string
): { data: RecruiterAnalysisData; evidence: EvidenceItem[]; score_modifier: number } {
  const email = normalizeEmail(emailInput);
  const senderDomain = extractDomainFromEmail(email);
  const isFree = isFreeEmailProvider(email);
  const evidence: EvidenceItem[] = [];
  let score_modifier = 0;

  let domainAlignment: RecruiterAnalysisData["domain_alignment"] = "UNKNOWN";

  if (claimedCompanyDomain) {
    const cleanCompanyDomain = claimedCompanyDomain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    if (senderDomain === cleanCompanyDomain) {
      domainAlignment = "EXACT_MATCH";
    } else if (senderDomain.endsWith(`.${cleanCompanyDomain}`)) {
      domainAlignment = "SUBSIDIARY_MATCH";
    } else if (isFree) {
      domainAlignment = "FREE_EMAIL";
    } else if (senderDomain.includes(cleanCompanyDomain.split('.')[0]) || (claimedCompanyName && senderDomain.includes(claimedCompanyName.toLowerCase().replace(/[^a-z0-9]/g, '')))) {
      domainAlignment = "LOOKALIKE";
    } else {
      domainAlignment = "MISMATCH";
    }
  } else if (isFree) {
    domainAlignment = "FREE_EMAIL";
  }

  const data: RecruiterAnalysisData = {
    email,
    normalized_email: email,
    sender_domain: senderDomain,
    company_domain: claimedCompanyDomain,
    domain_alignment: domainAlignment,
    free_email_provider: isFree,
    known_threat: false,
  };

  if (!email || !email.includes('@')) {
    return { data, evidence, score_modifier };
  }

  // 1. Evaluate Free Email Provider vs Corporate Claim
  if (isFree) {
    evidence.push({
      category: "RECRUITER",
      evidence_type: "FREE_WEBMAIL_SENDER",
      source_name: "Email Domain Authority Inspector",
      title: `Recruiter Uses Free Webmail Provider (@${senderDomain})`,
      snippet: `Communication originated from a public webmail domain (${senderDomain}) rather than an organizational domain.`,
      evidence_text: `Recruiter email '${email}' uses a public webmail provider. While common for freelancers and very small early-stage teams, established organizations exclusively issue official enterprise email addresses.`,
      evidence_strength: "MEDIUM",
      status: "WARNING",
      severity: "MEDIUM",
      verified: true,
      confidence: 90.0,
    });
    score_modifier -= 15;
  } else {
    evidence.push({
      category: "RECRUITER",
      evidence_type: "ORGANIZATIONAL_EMAIL_DOMAIN",
      source_name: "Email Domain Authority Inspector",
      title: `Corporate Domain Detected (@${senderDomain})`,
      snippet: `Sender address operates on custom domain '${senderDomain}'.`,
      evidence_text: `Communication originates from custom organizational domain '${senderDomain}'. Domain alignment requires the domain to also match the claimed company.`,
      evidence_strength: "STRONG",
      status: "VERIFIED",
      severity: "INFO",
      verified: true,
      confidence: 90.0,
    });
    score_modifier += 15;
  }

  // 2. Domain Alignment Assessment
  if (domainAlignment === "MISMATCH") {
    evidence.push({
      category: "CONSISTENCY",
      evidence_type: "RECRUITER_COMPANY_DOMAIN_MISMATCH",
      source_name: "Identity Alignment Engine",
      title: "Recruiter Domain Mismatch with Claimed Employer",
      snippet: `Sender domain '@${senderDomain}' does not match official company domain '${claimedCompanyDomain}'.`,
      evidence_text: `Sender claims to represent ${claimedCompanyName || 'the organization'} but dispatched the message from an unassociated domain '${senderDomain}'.`,
      evidence_strength: "STRONG",
      status: "NEGATIVE",
      severity: "HIGH",
      verified: true,
      confidence: 90.0,
    });
    score_modifier -= 25;
  } else if (domainAlignment === "EXACT_MATCH") {
    evidence.push({
      category: "CONSISTENCY",
      evidence_type: "RECRUITER_COMPANY_DOMAIN_ALIGNED",
      source_name: "Identity Alignment Engine",
      title: "Domain Alignment: Recruiter Domain Matches Company Domain",
      snippet: `Sender domain '@${senderDomain}' matches official corporate domain '${claimedCompanyDomain}'.`,
      evidence_text: `Sender address domain matches verified company web domain. NOTE: Domain alignment is a positive indicator, but does NOT independently prove that the specific individual is authorized to extend offers on behalf of the company.`,
      evidence_strength: "STRONG",
      status: "VERIFIED",
      severity: "INFO",
      verified: true,
      confidence: 90.0,
    });
    score_modifier += 15;
  }

  return { data, evidence, score_modifier };
}
