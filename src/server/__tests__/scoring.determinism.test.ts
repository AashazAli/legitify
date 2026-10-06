// ==============================================================================
// LEGITIFY FORENSIC SCORING DETERMINISM TESTS
// 
// Tests the core principle: SAME EVIDENCE → SAME SCORE
//                           DIFFERENT EVIDENCE → DIFFERENT SCORE
// ==============================================================================

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { calculateDeterministicScore, ScoringInputs, DEFAULT_SCORING_WEIGHTS } from '../services/scoringService';

// Minimal base inputs for testing
function makeBaseInputs(overrides: Partial<ScoringInputs> = {}): ScoringInputs {
  return {
    companyData: {
      legal_name: 'Test Corp Private Limited',
      registry_status: 'ACTIVE',
      status: 'ACTIVE',
      registration_number: 'U99999MH2020PTC123456',
      domain: 'testcorp.com',
    },
    domainData: {
      domain: 'testcorp.com',
      has_dns: true,
      mx_records: ['mail.testcorp.com'],
      a_records: ['192.0.2.1'],
      txt_records: ['v=spf1 include:_spf.testcorp.com ~all'],
      ssl_valid: true,
      ssl_issuer: 'Let\'s Encrypt',
      ssl_days_remaining: 60,
      age_days: 730,
      lookalike_detected: false,
    },
    recruiterData: {
      email: 'hr@testcorp.com',
      normalized_email: 'hr@testcorp.com',
      sender_domain: 'testcorp.com',
      company_domain: 'testcorp.com',
      domain_alignment: 'EXACT_MATCH',
      free_email_provider: false,
      known_threat: false,
    },
    documentData: {
      extracted_text: 'Dear Candidate, We are pleased to offer you the position of Software Engineer at Test Corp. Your gross CTC will be INR 8,00,000 per annum. Joining date: 15 March 2025. No registration fee or deposit is required.',
      has_fee_demand: false,
      is_confirmed_impersonation: false,
      is_suspicious_offer_letter: false,
      suspicious_patterns: [],
      extracted_entities: {},
      evidence: [],
      triggered_flags: [],
      dimension_scores: { rules: 80, nlp: 75, ner: 70 },
      final_score: 82,
      verdict: 'LIKELY GENUINE',
      next_steps: [],
    },
    mlPrediction: {
      fraudProbability: 0.08,
      legitimateProbability: 0.92,
      confidence: 0.87,
      prediction: 'LEGITIMATE',
      algorithm: 'Linear SVM',
      modelVersion: '1.2.0',
    },
    threatData: {
      known_threat: false,
      max_severity: 'NONE',
      threat_types: [],
      evidence: [],
    },
    communityData: {
      totalRelevantResults: 2,
      riskSignals: [],
      positiveSignals: ['Good company reviews on InternShala'],
      communityConfidence: 0.65,
      uniqueExperienceClusters: 1,
      evidence: [],
    },
    ...overrides,
  } as ScoringInputs;
}

describe('LEGITIFY Scoring: Determinism', () => {
  it('Same input produces identical output on repeated calls', () => {
    const inputs = makeBaseInputs();
    
    const result1 = calculateDeterministicScore(inputs);
    const result2 = calculateDeterministicScore(inputs);
    const result3 = calculateDeterministicScore(inputs);
    
    assert.strictEqual(result1.trust_score, result2.trust_score);
    assert.strictEqual(result2.trust_score, result3.trust_score);
    assert.strictEqual(result1.confidence_score, result2.confidence_score);
    assert.strictEqual(result1.risk_level, result2.risk_level);
    assert.strictEqual(result1.verdict, result2.verdict);
  });

  it('Score is NOT random — zero variance across 10 iterations', () => {
    const inputs = makeBaseInputs();
    const scores = Array.from({ length: 10 }, () => calculateDeterministicScore(inputs).trust_score);
    
    const uniqueScores = new Set(scores);
    assert.strictEqual(uniqueScores.size, 1);
  });

  it('Score is a valid integer in range (1-99)', () => {
    const inputs = makeBaseInputs();
    const result = calculateDeterministicScore(inputs);
    
    assert.ok(result.trust_score >= 1);
    assert.ok(result.trust_score <= 99);
    assert.ok(Number.isInteger(result.trust_score));
  });
});

describe('LEGITIFY Scoring: Dynamic (Different Evidence → Different Score)', () => {
  it('Case 1 vs Case 2: Adding fee demand significantly lowers score', () => {
    const legitimate = makeBaseInputs();
    const legitimateScore = calculateDeterministicScore(legitimate);
    
    const withFee = makeBaseInputs({
      documentData: {
        ...makeBaseInputs().documentData!,
        extracted_text: 'Dear Candidate, you must pay a security deposit of Rs 5000 via UPI to confirm your joining.',
        has_fee_demand: true,
      },
    });
    const withFeeScore = calculateDeterministicScore(withFee);
    
    assert.ok(withFeeScore.trust_score < legitimateScore.trust_score, `Expected ${withFeeScore.trust_score} < ${legitimateScore.trust_score}`);
    assert.ok(withFeeScore.trust_score <= 20, `Expected score <= 20 with fee demand, got ${withFeeScore.trust_score}`);
    assert.ok(withFeeScore.hard_caps_applied.some(c => c.includes('PAYMENT_REQUEST_CAP') || c.includes('candidate payment')));
  });

  it('Case 3: Recruiter switching from corporate to Gmail lowers score', () => {
    const withCorporateEmail = makeBaseInputs();
    const corpScore = calculateDeterministicScore(withCorporateEmail);
    
    const withGmailEmail = makeBaseInputs({
      recruiterData: {
        email: 'recruiter.testcorp@gmail.com',
        normalized_email: 'recruiter.testcorp@gmail.com',
        sender_domain: 'gmail.com',
        company_domain: 'testcorp.com',
        domain_alignment: 'FREE_EMAIL',
        free_email_provider: true,
        known_threat: false,
      },
    });
    const gmailScore = calculateDeterministicScore(withGmailEmail);
    
    assert.ok(gmailScore.trust_score < corpScore.trust_score, `Expected ${gmailScore.trust_score} < ${corpScore.trust_score}`);
    assert.ok(gmailScore.warning_signals.some(s => s.toLowerCase().includes('webmail') || s.toLowerCase().includes('gmail')));
  });

  it('Case 4: Lookalike domain caps score at 25', () => {
    const legitimate = makeBaseInputs();
    const legitScore = calculateDeterministicScore(legitimate);
    
    const withLookalike = makeBaseInputs({
      domainData: {
        ...makeBaseInputs().domainData!,
        domain: 'testcorp-careers.in',
        lookalike_detected: true,
        lookalike_target: 'testcorp.com',
      },
    });
    const lookalikeScore = calculateDeterministicScore(withLookalike);
    
    assert.ok(lookalikeScore.trust_score < legitScore.trust_score);
    assert.ok(lookalikeScore.trust_score <= 25, `Expected score <= 25 for lookalike domain, got ${lookalikeScore.trust_score}`);
    assert.ok(lookalikeScore.hard_caps_applied.some(c => c.includes('LOOKALIKE')));
  });

  it('Case 5: Registry unavailable does NOT falsely add critical risk flags', () => {
    const withoutRegistry = makeBaseInputs({ companyData: undefined });
    const withoutRegistryScore = calculateDeterministicScore(withoutRegistry);
    
    const criticalRegistrySignals = withoutRegistryScore.critical_signals.filter(
      s => s.toLowerCase().includes('registry') || s.toLowerCase().includes('mca')
    );
    assert.strictEqual(criticalRegistrySignals.length, 0);
  });
});

describe('LEGITIFY Scoring: Monotonic Risk Property', () => {
  it('Payment evidence severity is monotonically risky', () => {
    const noPayment = makeBaseInputs();
    const withFee = makeBaseInputs({
      documentData: {
        ...makeBaseInputs().documentData!,
        has_fee_demand: true,
        extracted_text: 'Pay Rs 5000 registration fee',
      },
    });
    const withConfirmedImpersonation = makeBaseInputs({
      documentData: {
        ...makeBaseInputs().documentData!,
        has_fee_demand: true,
        is_confirmed_impersonation: true,
        extracted_text: 'This is an impersonation offer. Pay Rs 5000.',
      },
    });
    
    const scoreNoPayment = calculateDeterministicScore(noPayment).trust_score;
    const scoreWithFee = calculateDeterministicScore(withFee).trust_score;
    const scoreWithImpersonation = calculateDeterministicScore(withConfirmedImpersonation).trust_score;
    
    assert.ok(scoreWithFee <= scoreNoPayment);
    assert.ok(scoreWithImpersonation <= scoreWithFee);
  });
});

describe('LEGITIFY Scoring: 10 Dimensions and Weights Integrity', () => {
  it('Scoring weights sum to exactly 1.0', () => {
    const sum = Object.values(DEFAULT_SCORING_WEIGHTS).reduce((a, b) => a + b, 0);
    assert.ok(Math.abs(sum - 1.0) < 0.0001, `Weights sum to ${sum}, expected 1.0`);
  });

  it('All 10 dimension weights are positive and non-zero', () => {
    const weightKeys = Object.keys(DEFAULT_SCORING_WEIGHTS);
    assert.strictEqual(weightKeys.length, 10, `Expected 10 dimension weights, got ${weightKeys.length}`);
    
    for (const [dim, weight] of Object.entries(DEFAULT_SCORING_WEIGHTS)) {
      assert.ok(weight > 0, `Weight for ${dim} must be > 0`);
      assert.ok(weight <= 1.0, `Weight for ${dim} must be <= 1.0`);
    }
  });

  it('Calculated components contain all 10 dimensions', () => {
    const inputs = makeBaseInputs();
    const result = calculateDeterministicScore(inputs);
    
    const componentKeys = Object.keys(result.components);
    assert.strictEqual(componentKeys.length, 10, `Expected 10 component breakdowns, got ${componentKeys.length}`);
    assert.ok(result.components.document_authenticity);
    assert.ok(result.components.company);
    assert.ok(result.components.domain);
    assert.ok(result.components.recruiter);
    assert.ok(result.components.document);
    assert.ok(result.components.certificate);
    assert.ok(result.components.ml_probability);
    assert.ok(result.components.threat);
    assert.ok(result.components.community);
    assert.ok(result.components.consistency);
  });
});
