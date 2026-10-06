// ==============================================================================
// LEGITIFY EVIDENCE LEDGER SERVICE
// Manages evidence with full provenance, source hierarchy, authority tiers,
// freshness, reliability, and mathematical effective contribution.
// ==============================================================================

import {
  ForensicEvidence,
  EvidenceType,
  EvidenceDirection,
  EvidenceAvailability,
  EvidenceSource,
} from '../../types/forensicTypes';
import { EvidenceItem } from '../../types';

export interface EvidenceLedgerState {
  evidence: ForensicEvidence[];
  evidenceMap: Map<string, ForensicEvidence>;
}

export class EvidenceLedger {
  private items: ForensicEvidence[] = [];
  private counter: number = 0;
  private scanId: string;

  constructor(scanId: string) {
    this.scanId = scanId;
  }

  /**
   * Add an evidence item with full audit provenance.
   * Calculates effective contribution deterministically:
   * effectiveContribution = strength * reliability * authority * freshness
   */
  public addEvidence(params: {
    type: EvidenceType;
    source: EvidenceSource;
    direction: EvidenceDirection;
    strength: number;       // 0-1
    reliability: number;    // 0-1
    freshness?: number;     // 0-1 (default 1.0)
    finding: string;
    explanation: string;
    availability: EvidenceAvailability;
    relatedClaimIds?: string[];
    dimension: string;
    customId?: string;
  }): ForensicEvidence {
    this.counter++;
    const id = params.customId || `${this.scanId}-E-${String(this.counter).padStart(3, '0')}`;

    // Authority is derived from source tier:
    // Tier 1 (Statutory/Official): 1.0
    // Tier 2 (Established Security/Journalism): 0.8
    // Tier 3 (Independent Public Reports/Forums): 0.5
    // Tier 4 (Unverified/Anonymous): 0.2
    const authority = params.source.tier === 1 ? 1.0
      : params.source.tier === 2 ? 0.8
      : params.source.tier === 3 ? 0.5
      : 0.2;

    const freshness = params.freshness !== undefined ? params.freshness : 1.0;
    const effectiveContribution = Number(
      (params.strength * params.reliability * authority * freshness).toFixed(4)
    );

    const item: ForensicEvidence = {
      evidenceId: id,
      type: params.type,
      source: params.source,
      direction: params.direction,
      strength: params.strength,
      reliability: params.reliability,
      authority,
      freshness,
      effectiveContribution,
      finding: params.finding,
      explanation: params.explanation,
      availability: params.availability,
      retrievedAt: new Date().toISOString(),
      relatedClaimIds: params.relatedClaimIds || [],
      dimension: params.dimension,
    };

    this.items.push(item);
    return item;
  }

  public getAll(): ForensicEvidence[] {
    return [...this.items];
  }

  public getById(id: string): ForensicEvidence | undefined {
    return this.items.find(e => e.evidenceId === id);
  }

  public getByDimension(dimension: string): ForensicEvidence[] {
    return this.items.filter(e => e.dimension === dimension);
  }

  public getRiskEvidence(): ForensicEvidence[] {
    return this.items.filter(e => e.direction === 'RISK');
  }

  public getLegitimacyEvidence(): ForensicEvidence[] {
    return this.items.filter(e => e.direction === 'LEGITIMACY');
  }

  /**
   * Convert to legacy EvidenceItem format for backward compatibility with UI components.
   */
  public toLegacyEvidenceItems(): EvidenceItem[] {
    return this.items.map(e => ({
      evidence_id: e.evidenceId,
      category: e.dimension.toUpperCase(),
      evidence_type_category: e.direction === 'RISK' ? 'RISK_SIGNAL' : 'AUTHENTICITY_SIGNAL',
      evidence_type: e.type,
      source_name: e.source.name,
      source_url: e.source.url,
      title: e.finding,
      snippet: e.explanation,
      evidence_text: e.explanation,
      evidence_strength: e.strength >= 0.8 ? 'STRONG' : e.strength >= 0.5 ? 'MODERATE' : 'WEAK',
      status: e.direction === 'RISK' ? (e.strength >= 0.8 ? 'CRITICAL' : 'WARNING') : 'VERIFIED',
      severity: e.direction === 'RISK' ? (e.strength >= 0.8 ? 'CRITICAL' : 'HIGH') : 'LOW',
      verified: e.availability === 'LIVE_VERIFIED' || e.availability === 'LOCAL_REFERENCE',
      confidence: Math.round(e.reliability * 100),
    } as any));
  }
}
