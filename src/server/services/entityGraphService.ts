// ==============================================================================
// LEGITIFY ENTITY RELATIONSHIP GRAPH SERVICE
// Builds relationship graph of Company, Recruiter, Domain, Offer, Payment, Signatory
// Evaluates relationship consistency and cross-signal contradictions
// ==============================================================================

import {
  GraphAnomaly,
  ForensicClaim,
  DocumentChunk,
} from '../../types/forensicTypes';
import { GraphNode, GraphEdge, EntityGraphData } from '../../types';
import { normalizeDomain, normalizeCompanyName, isFreeEmailProvider } from '../utils/normalizer';

export interface ForensicEntityGraphResult extends EntityGraphData {
  anomalies: GraphAnomaly[];
  coherenceScore: number;
}

export interface EntityGraphInput {
  companyName?: string;
  officialDomain?: string;
  recruiterEmail?: string;
  recruiterName?: string;
  domain?: string;
  claims: ForensicClaim[];
  chunks: DocumentChunk[];
  stipend?: string;
  salary?: string;
  joiningDate?: string;
  offerDate?: string;
  hasPaymentRequest?: boolean;
  paymentAmount?: string;
  paymentMethod?: string;
  upiId?: string;
  signatoryName?: string;
  signatoryTitle?: string;
}

/**
 * Builds the Entity Relationship Graph from extracted claims and verified records.
 * Deterministic: same inputs produce identical graph and anomalies.
 */
export function buildEntityGraph(input: EntityGraphInput): ForensicEntityGraphResult {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const anomalies: GraphAnomaly[] = [];

  const company = input.companyName ? normalizeCompanyName(input.companyName) : 'Unknown Organization';
  const claimedDomain = input.domain ? normalizeDomain(input.domain) : undefined;
  const recruiterEmail = input.recruiterEmail?.toLowerCase().trim();
  const recruiterDomain = recruiterEmail && recruiterEmail.includes('@')
    ? recruiterEmail.split('@')[1]
    : undefined;

  // 1. Nodes
  // Company Node
  const companyNodeId = 'NODE-COMPANY-01';
  nodes.push({
    id: companyNodeId,
    type: 'company',
    label: company,
    status: input.officialDomain ? 'verified' : 'neutral',
    details: input.officialDomain ? `Official domain: ${input.officialDomain}` : 'Company entity identified',
  });

  // Offer Node
  const offerNodeId = 'NODE-OFFER-01';
  nodes.push({
    id: offerNodeId,
    type: 'offer',
    label: 'Employment / Internship Opportunity',
    status: input.hasPaymentRequest ? 'suspicious' : 'neutral',
    details: input.claims.find(c => c.type === 'ROLE_TITLE')?.normalizedValue || 'Target role unspecified',
  });
  edges.push({
    from: offerNodeId,
    to: companyNodeId,
    label: 'CLAIMS_COMPANY',
    type: 'REFERENCES',
    status: 'neutral',
  });

  // Domain Node (if present)
  let domainNodeId: string | undefined;
  if (claimedDomain) {
    domainNodeId = 'NODE-DOMAIN-01';
    nodes.push({
      id: domainNodeId,
      type: 'domain',
      label: claimedDomain,
      status: 'neutral',
      details: `Referenced web domain: ${claimedDomain}`,
    });
    edges.push({
      from: offerNodeId,
      to: domainNodeId,
      label: 'LISTED_DOMAIN',
      type: 'REFERENCES',
      status: 'neutral',
    });
  }

  // Recruiter Node (if present)
  let recruiterNodeId: string | undefined;
  if (recruiterEmail) {
    recruiterNodeId = 'NODE-RECRUITER-01';
    const isFree = isFreeEmailProvider(recruiterEmail);
    nodes.push({
      id: recruiterNodeId,
      type: 'recruiter',
      label: input.recruiterName || recruiterEmail,
      status: isFree ? 'suspicious' : 'neutral',
      details: isFree ? 'Public webmail provider (@gmail/@yahoo)' : `Corporate recruiter (@${recruiterDomain})`,
    });
    edges.push({
      from: offerNodeId,
      to: recruiterNodeId,
      label: 'SENDER_EMAIL',
      type: 'SENDS',
      status: isFree ? 'suspicious' : 'neutral',
    });

    if (recruiterDomain && domainNodeId) {
      edges.push({
        from: recruiterNodeId,
        to: domainNodeId,
        label: 'RECRUITER_DOMAIN',
        type: 'USES',
        status: recruiterDomain === claimedDomain ? 'verified' : 'suspicious',
      });
    }
  }

  // Payment Node (if payment detected)
  if (input.hasPaymentRequest || input.paymentAmount || input.upiId) {
    const paymentNodeId = 'NODE-PAYMENT-01';
    nodes.push({
      id: paymentNodeId,
      type: 'threat',
      label: `Candidate Payment Requirement: ${input.paymentAmount || 'Fee Demanded'}`,
      status: 'threat',
      details: input.upiId ? `Payment channel: UPI (${input.upiId})` : 'Upfront onboarding fee condition',
    });
    edges.push({
      from: offerNodeId,
      to: paymentNodeId,
      label: 'DEMANDS_PAYMENT',
      type: 'FLAGGED_BY',
      status: 'threat',
    });
  }

  // Signatory Node (if present)
  if (input.signatoryName) {
    const signatoryNodeId = 'NODE-SIGNATORY-01';
    nodes.push({
      id: signatoryNodeId,
      type: 'document',
      label: `${input.signatoryName} (${input.signatoryTitle || 'Signatory'})`,
      status: 'neutral',
      details: `Signatory designation: ${input.signatoryTitle || 'Authorized Signatory'}`,
    });
    edges.push({
      from: offerNodeId,
      to: signatoryNodeId,
      label: 'SIGNED_BY',
      type: 'AUTHORED',
      status: 'neutral',
    });
  }

  // 2. Anomaly Detection & Cross-Signal Integrity
  // A. Domain Mismatch
  if (input.officialDomain && recruiterDomain && !isFreeEmailProvider(recruiterEmail || '')) {
    const normOfficial = normalizeDomain(input.officialDomain);
    const normRecruiter = normalizeDomain(recruiterDomain);
    if (normOfficial !== normRecruiter && !normRecruiter.endsWith(`.${normOfficial}`)) {
      anomalies.push({
        id: 'ANOM-001',
        anomalyType: 'DOMAIN_MISMATCH',
        severity: 'HIGH',
        description: `Recruiter email domain (@${normRecruiter}) does not match official company domain (@${normOfficial}).`,
        involvedNodes: [companyNodeId, recruiterNodeId || ''],
        resolution: 'Candidate should verify recruiter authorization directly via the official corporate switchboard.',
      });
    }
  }

  // B. Enterprise On Free Mailbox
  if (recruiterEmail && isFreeEmailProvider(recruiterEmail)) {
    const isEnterprise = company.length > 3 && !company.toLowerCase().includes('freelance');
    if (isEnterprise) {
      anomalies.push({
        id: 'ANOM-002',
        anomalyType: 'ENTERPRISE_ON_FREE_MAILBOX',
        severity: 'HIGH',
        description: `Recruiter is using a public webmail mailbox (${recruiterEmail}) while representing established entity ${company}.`,
        involvedNodes: [companyNodeId, recruiterNodeId || ''],
        resolution: 'Established commercial enterprises do not conduct official hiring or dispatch offer letters from generic public webmail accounts.',
      });
    }
  }

  // C. Compensation Contradiction
  const compensationClaims = input.claims.filter(
    c => c.type === 'STIPEND' || c.type === 'SALARY'
  );
  if (compensationClaims.length >= 2) {
    const vals = compensationClaims.map(c => c.normalizedValue.replace(/[^\d]/g, '')).filter(Boolean);
    const uniqueVals = [...new Set(vals)];
    if (uniqueVals.length > 1) {
      const minVal = Math.min(...uniqueVals.map(Number));
      const maxVal = Math.max(...uniqueVals.map(Number));
      if (maxVal > minVal * 3) {
        anomalies.push({
          id: 'ANOM-003',
          anomalyType: 'COMPENSATION_CONTRADICTION',
          severity: 'MEDIUM',
          description: `Internal compensation terms conflict: document cites multiple divergent compensation figures (${compensationClaims.map(c => c.normalizedValue).join(' vs ')}).`,
          involvedNodes: [offerNodeId],
          resolution: 'Inconsistent compensation figures are typical of template-spliced fraudulent offer letters.',
        });
      }
    }
  }

  // D. Temporal Sequence Violation
  if (input.offerDate && input.joiningDate) {
    const offerMs = Date.parse(input.offerDate);
    const joinMs = Date.parse(input.joiningDate);
    if (!isNaN(offerMs) && !isNaN(joinMs) && joinMs < offerMs) {
      anomalies.push({
        id: 'ANOM-004',
        anomalyType: 'TEMPORAL_SEQUENCE_VIOLATION',
        severity: 'HIGH',
        description: `Date sequence contradiction: Joining date (${input.joiningDate}) occurs before offer issuance date (${input.offerDate}).`,
        involvedNodes: [offerNodeId],
        resolution: 'Chronological timeline contradictions strongly indicate careless document fabrication.',
      });
    }
  }

  // 3. Coherence Score (100 base, deducted by anomaly severities)
  let coherence = 100;
  for (const anom of anomalies) {
    if (anom.severity === 'CRITICAL') coherence -= 40;
    else if (anom.severity === 'HIGH') coherence -= 25;
    else if (anom.severity === 'MEDIUM') coherence -= 15;
    else coherence -= 5;
  }
  coherence = Math.max(0, Math.min(100, coherence));

  return {
    nodes,
    edges,
    anomalies,
    coherenceScore: coherence,
  };
}
