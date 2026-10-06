// ==============================================================================
// LEGITIFY DYNAMIC ENTITY GRAPH BUILDER
// Visualizes multi-hop relationships between Company, Domain, Recruiter, Offer, Certificate, and Threats
// ==============================================================================
import { EntityGraphData, GraphNode, GraphEdge, CertificateVerificationData } from '../../types';
import { CompanyData } from './companyService';
import { DomainData } from './domainService';
import { RecruiterData } from './emailService';
import { DocumentExtractionResult } from './documentService';
import { ThreatData } from './threatService';

export function buildEntityGraph(ctx: {
  entityName: string;
  entityType: string;
  companyData?: CompanyData;
  domainData?: DomainData;
  recruiterData?: RecruiterData;
  documentData?: DocumentExtractionResult;
  certificateData?: CertificateVerificationData;
  threatData?: ThreatData;
}): EntityGraphData {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // 1. Company Node
  const compId = "node-company";
  const compName = ctx.companyData?.legal_name || ctx.entityName || "Target Company";
  nodes.push({
    id: compId,
    label: compName,
    type: "company",
    status: ctx.companyData?.status === "ACTIVE" ? "verified" : "neutral",
    details: ctx.companyData?.registration_number ? `Reg: ${ctx.companyData.registration_number}` : "Entity",
  });

  // 2. Domain Node
  if (ctx.domainData?.domain || ctx.companyData?.domain) {
    const domId = "node-domain";
    const domName = ctx.domainData?.domain || ctx.companyData?.domain || "Domain";
    const isLookalike = ctx.domainData?.lookalike_detected;
    nodes.push({
      id: domId,
      label: domName,
      type: "domain",
      status: isLookalike ? "threat" : ctx.domainData?.has_dns ? "verified" : "neutral",
      details: ctx.domainData?.age_days !== undefined ? `Age: ${ctx.domainData.age_days}d` : "Domain",
    });

    edges.push({
      from: compId,
      to: domId,
      label: isLookalike ? "SPOOFED_BY" : "OWNS",
      type: isLookalike ? "SPOOFED_BY" : "OWNS",
      status: isLookalike ? "threat" : "verified",
    });
  }

  // 3. Recruiter Node
  if (ctx.recruiterData?.email) {
    const recId = "node-recruiter";
    const isFree = ctx.recruiterData.is_free_provider;
    nodes.push({
      id: recId,
      label: ctx.recruiterData.email,
      type: "recruiter",
      status: isFree ? "suspicious" : ctx.recruiterData.domain_alignment === "MATCH" ? "verified" : "neutral",
      details: isFree ? "Public Webmail" : "Corporate Handle",
    });

    const domNode = nodes.find(n => n.type === "domain");
    if (domNode) {
      edges.push({
        from: domNode.id,
        to: recId,
        label: isFree ? "USES_PUBLIC_WEBMAIL" : "SENDS",
        type: "SENDS",
        status: isFree ? "suspicious" : "verified",
      });
    } else {
      edges.push({
        from: compId,
        to: recId,
        label: "COMMUNICATES_AS",
        type: "USES",
        status: isFree ? "suspicious" : "verified",
      });
    }
  }

  // 4. Offer / Document Node
  if (ctx.documentData || ctx.entityType === 'job_offer' || ctx.entityType === 'offer') {
    const offId = "node-offer";
    const hasFee = ctx.documentData?.has_fee_demand;
    nodes.push({
      id: offId,
      label: ctx.documentData?.filename || "Offer Document",
      type: "offer",
      status: hasFee ? "threat" : "neutral",
      details: hasFee ? "Fee Demand Flagged" : "Internship Offer",
    });

    const recNode = nodes.find(n => n.type === "recruiter");
    if (recNode) {
      edges.push({
        from: recNode.id,
        to: offId,
        label: "AUTHORED",
        type: "AUTHORED",
        status: hasFee ? "threat" : "neutral",
      });
    } else {
      edges.push({
        from: compId,
        to: offId,
        label: "ISSUES",
        type: "AUTHORED",
        status: hasFee ? "threat" : "neutral",
      });
    }
  }

  // 5. Certificate & Issuer Node
  if (ctx.certificateData) {
    const certId = "node-certificate";
    const certStatus = ctx.certificateData.status;
    nodes.push({
      id: certId,
      label: ctx.certificateData.certificate_id ? `Cert #${ctx.certificateData.certificate_id}` : "Credentials Certificate",
      type: "certificate",
      status: certStatus === "VERIFIED_AUTHENTIC" ? "verified" : certStatus === "LIKELY_FRAUDULENT" ? "threat" : "unverified",
      details: `Status: ${certStatus}`,
    });

    if (ctx.certificateData.issuer_name) {
      const issuerId = "node-issuer";
      nodes.push({
        id: issuerId,
        label: ctx.certificateData.issuer_name,
        type: "issuer",
        status: ctx.certificateData.issuer_verified ? "verified" : "unverified",
        details: ctx.certificateData.issuer_domain || "Issuer Entity",
      });

      edges.push({
        from: certId,
        to: issuerId,
        label: "ISSUED_BY",
        type: "ISSUED_BY",
        status: ctx.certificateData.issuer_verified ? "verified" : "neutral",
      });
    }

    const offerNode = nodes.find(n => n.type === "offer");
    if (offerNode) {
      edges.push({
        from: offerNode.id,
        to: certId,
        label: "REFERENCES",
        type: "REFERENCES",
        status: certStatus === "VERIFIED_AUTHENTIC" ? "verified" : "neutral",
      });
    }
  }

  // 6. Threat Node
  const threatMatches = ctx.threatData?.matches || (ctx.threatData as any)?.indicators || [];
  if (threatMatches.length > 0) {
    const threatId = "node-threat";
    nodes.push({
      id: threatId,
      label: `${threatMatches.length} Threat IOC Matches`,
      type: "threat",
      status: "threat",
      details: threatMatches[0]?.threat_type || "Threat Feed Match",
    });

    // Attach threat node to affected entity (domain or recruiter or company)
    const targetNode = nodes.find(n => n.type === "domain") || nodes.find(n => n.type === "recruiter") || nodes[0];
    if (targetNode) {
      edges.push({
        from: threatId,
        to: targetNode.id,
        label: "FLAGGED_BY",
        type: "FLAGGED_BY",
        status: "threat",
      });
    }
  }

  return { nodes, edges };
}
