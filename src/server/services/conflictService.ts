// ==============================================================================
// CROSS-SOURCE EVIDENCE CONFLICT DETECTION SERVICE
// Explicitly identifies and explains contradictory evidence without suppressing facts
// ==============================================================================
import { EvidenceItem, CertificateStatus } from '../../types';
import { CompanyData } from './companyService';
import { DomainData } from './domainService';
import { RecruiterData } from './emailService';
import { MLPrediction } from '../ml/fraudClassifier';
import { ThreatData } from './threatService';

export interface EvidenceConflict {
  conflictId: string;
  title: string;
  description: string;
  positiveSide: string;
  negativeSide: string;
  severity: "HIGH" | "MEDIUM" | "INFO";
}

export function detectEvidenceConflicts(params: {
  companyData?: CompanyData;
  domainData?: DomainData;
  recruiterData?: RecruiterData;
  certificateStatus?: CertificateStatus;
  mlPrediction?: MLPrediction;
  threatData?: ThreatData;
  hasFeeDemand?: boolean;
  communityNegativeCount?: number;
  communityPositiveCount?: number;
}): EvidenceConflict[] {
  const conflicts: EvidenceConflict[] = [];

  // Conflict 1: Registered Company BUT Lookalike / Impersonated Domain
  if (params.companyData?.registry_status === 'VERIFIED' && params.domainData?.lookalike_detected) {
    conflicts.push({
      conflictId: "C001",
      title: "Legitimate Corporate Registration vs. Lookalike Domain Impersonation",
      description: "An organization with this legal name appears in the official statutory registry, but the domain used in this communication is a lookalike/typosquatted domain mimicking the official organization.",
      positiveSide: `Company '${params.companyData.legal_name}' is active and verified in corporate registry.`,
      negativeSide: `Domain '${params.domainData.domain}' mimics ${params.domainData.lookalike_target || 'the brand'} and is not owned by the legal entity.`,
      severity: "HIGH",
    });
  }

  // Conflict 2: Authentic Certificate BUT Actual Fee Demand in the Internship
  // NOTE: Only fire on concrete fraud evidence (fee demand), NOT on ML prediction alone.
  // ML false positives must not penalize legitimate offers with verified certificates.
  if (params.certificateStatus === 'VERIFIED_AUTHENTIC' && params.hasFeeDemand) {
    conflicts.push({
      conflictId: "C002",
      title: "Authentic Educational Certificate vs. Fee-Demanding Internship Opportunity",
      description: "The attached certificate credential conforms to valid cryptographic issuer standards, but the internship offer itself demands upfront candidate fees — a hallmark of recruitment fraud.",
      positiveSide: "Certificate identifier and issuer format are independently verified authentic.",
      negativeSide: "Internship opportunity requests mandatory monetary fees from the candidate.",
      severity: "HIGH",
    });
  }

  // Conflict 3: Corporate Employer Claimed BUT Recruiter Uses Public Free Webmail
  if (params.companyData?.registry_status === 'VERIFIED' && params.recruiterData?.free_email_provider) {
    conflicts.push({
      conflictId: "C003",
      title: "Statutory Enterprise Claimed vs. Free Public Webmail Communication",
      description: "The offer claims affiliation with a major corporate enterprise, but the recruiter is communicating through an anonymous public email provider (e.g. Gmail/Yahoo).",
      positiveSide: `Claimed entity '${params.companyData.legal_name}' is a recognized statutory corporation.`,
      negativeSide: `Recruiter email '${params.recruiterData.email}' uses a public webmail domain rather than the corporate domain.`,
      severity: "MEDIUM",
    });
  }

  // Conflict 4: ML Predicts Low Risk BUT Direct Threat Feed IOC Match
  if (params.mlPrediction && params.mlPrediction.fraudProbability < 0.30 && params.threatData?.known_threat) {
    conflicts.push({
      conflictId: "C004",
      title: "Clean NLP Text Signals vs. Direct Threat Intelligence IOC Match",
      description: "The text structure appears professional and well-formatted, but the domain or contact identifier is listed on active security threat feeds.",
      positiveSide: "Job offer text exhibits standard professional corporate wording.",
      negativeSide: "Direct threat intelligence feed match identified active malicious indicators.",
      severity: "HIGH",
    });
  }

  // Conflict 5: Positive Historical Reputation BUT Recent Community Payment Complaints
  if ((params.communityPositiveCount || 0) > 0 && (params.communityNegativeCount || 0) > 0) {
    conflicts.push({
      conflictId: "C005",
      title: "Mixed Public Experiences: Genuine Programs vs. Fee Complaints",
      description: "Historical discussions confirm legitimate programs, but recent community complaints report unauthorized fee demands or impersonation.",
      positiveSide: "Positive candidate experiences on official campus programs.",
      negativeSide: "Unverified community reports detailing upfront registration fee requests.",
      severity: "MEDIUM",
    });
  }

  // Conflict 6: Document Claimed Website vs. Verified Official Web Domain
  if (params.domainData?.domain && params.companyData?.domain && params.domainData.domain !== params.companyData.domain) {
    conflicts.push({
      conflictId: "C006",
      title: "Document Contact Domain vs. Verified Enterprise Website",
      description: `The communication cites domain '${params.domainData.domain}', whereas the corporate registry indexes '${params.companyData.domain}' as the official web property.`,
      positiveSide: `Verified corporate headquarters domain is '${params.companyData.domain}'.`,
      negativeSide: `Submitted document routes to '${params.domainData.domain}'.`,
      severity: "HIGH",
    });
  }

  return conflicts;
}

export function formatContradictionsForReport(conflicts: EvidenceConflict[]): {
  type: string;
  field: string;
  claimed_value: string;
  verified_value: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  detail: string;
}[] {
  return conflicts.map(c => ({
    type: c.conflictId,
    field: c.title,
    claimed_value: c.negativeSide,
    verified_value: c.positiveSide,
    severity: c.severity === 'HIGH' ? 'CRITICAL' : c.severity === 'MEDIUM' ? 'HIGH' : 'INFO',
    detail: c.description,
  }));
}

