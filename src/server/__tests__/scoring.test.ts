import { describe, it } from 'node:test';
import assert from 'node:assert';
import { calculateDeterministicScore } from '../services/scoringService';
import { EvidenceItem } from '../../types';

describe('Deterministic Scoring Engine', () => {
  it('assigns high trust and low risk for verified corporate signals', () => {
    const evidence: EvidenceItem[] = [
      {
        category: 'COMPANY',
        source_name: 'MCA',
        title: 'Active Corporate Registration',
        evidence_strength: 'STRONG',
        status: 'VERIFIED',
        severity: 'INFO',
        verified: true,
        confidence: 95,
      },
      {
        category: 'DOMAIN',
        source_name: 'RDAP',
        title: 'Established Domain (5 yrs)',
        evidence_strength: 'STRONG',
        status: 'VERIFIED',
        severity: 'INFO',
        verified: true,
        confidence: 95,
      },
    ];

    const result = calculateDeterministicScore({
      companyData: {
        legal_name: 'Tata Consultancy Services',
        normalized_name: 'tcs',
        registration_number: 'L22210MH1995PLC084781',
        status: 'ACTIVE',
        registry_status: 'VERIFIED' as any,
        domain: 'tcs.com',
      } as any,
      domainData: {
        domain: 'tcs.com',
        has_dns: true,
        ssl_valid: true,
        age_days: 1500,
        lookalike_detected: false,
      } as any,
      recruiterData: {
        email: 'recruitment@tcs.com',
        domain: 'tcs.com',
        domain_alignment: 'EXACT_MATCH' as any,
        is_free_provider: false,
      } as any,
      evidence,
    });

    assert.ok(result.trust_score >= 70, `Expected score >= 70, got ${result.trust_score}`);
    assert.ok(result.verdict === 'LOW RISK' || result.verdict === 'LIKELY LEGITIMATE');
  });

  it('assigns critical risk penalty when fee demand is detected in document', () => {
    const evidence: EvidenceItem[] = [
      {
        category: 'DOCUMENT',
        source_name: 'Document Parser',
        title: 'Upfront Fee / Payment Request Detected',
        evidence_strength: 'VERY_STRONG',
        status: 'NEGATIVE',
        severity: 'CRITICAL',
        verified: true,
        confidence: 95,
      },
    ];

    const result = calculateDeterministicScore({
      documentData: {
        extracted_text: 'Please pay Rs. 4,500 security deposit to join.',
        has_fee_demand: true,
        requested_fees: [{ amount: '4500', reason: 'Deposit' }],
        suspicious_patterns: ['Fee demand'],
        extracted_entities: {},
        evidence,
      } as any,
      evidence,
    });

    assert.ok(result.trust_score <= 40, `Expected score <= 40, got ${result.trust_score}`);
    assert.ok(result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH');
  });
});
