// ==============================================================================
// LEGITIFY FEE DETECTION TESTS
// 
// Tests the critical requirement: Fee detection must understand NEGATION.
// "No registration fee required" ≠ fee demand.
// ==============================================================================

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chunkDocument, analyzeChunk } from '../services/chunkingService';

describe('Fee Detection: Positive Cases (Fee IS Present)', () => {
  const feeTexts = [
    {
      case: 'Direct amount + UPI',
      text: 'Please pay Rs 3500 security deposit via UPI ID abc@paytm before your joining date.',
    },
    {
      case: 'Registration fee',
      text: 'A registration fee of INR 2000 is required to confirm your internship slot.',
    },
    {
      case: 'Training kit fee',
      text: 'You must purchase the training kit worth Rs 4500 from us before starting.',
    },
    {
      case: 'Laptop security deposit',
      text: 'A laptop security deposit of Rs 15000 is mandatory. Transfer to our bank account.',
    },
    {
      case: 'Processing fee',
      text: 'Processing fee of 1500 rupees required. Pay via NEFT/IMPS.',
    },
  ];

  for (const tc of feeTexts) {
    it(`Detects fee: ${tc.case}`, () => {
      const chunks = chunkDocument(tc.text, 'DOC-TEST', {});
      assert.ok(chunks.length > 0);
      
      const findings = analyzeChunk(chunks[0]);
      assert.strictEqual(findings.paymentSignals.hasPaymentRequest, true);
      assert.strictEqual(findings.paymentSignals.hasPaymentNegation, false);
      assert.ok(findings.paymentSignals.confidence > 0.3);
    });
  }
});

describe('Fee Detection: Negation Cases (Fee is NOT Present)', () => {
  const noFeeTexts = [
    {
      case: 'Explicit no fee statement',
      text: 'We do not charge any registration fee. No payment is required from candidates.',
    },
    {
      case: 'Free of charge',
      text: 'This internship program is completely free of charge. No fees apply.',
    },
    {
      case: 'Will not collect fees',
      text: 'TCS will never charge candidates for interviews, offer letters, or joining formalities.',
    },
    {
      case: 'Fee not required',
      text: 'Registration fee is not required. All training materials are provided by the company.',
    },
    {
      case: 'Company pays all',
      text: 'All expenses including travel and accommodation will be borne by the company.',
    },
  ];

  for (const tc of noFeeTexts) {
    it(`Does NOT falsely flag negation: ${tc.case}`, () => {
      const chunks = chunkDocument(tc.text, 'DOC-TEST', {});
      assert.ok(chunks.length > 0);
      
      const findings = analyzeChunk(chunks[0]);
      assert.strictEqual(findings.paymentSignals.hasPaymentRequest, false, `Expected no payment request for: "${tc.text}"`);
    });
  }
});

describe('Fee Detection: Ambiguous Cases', () => {
  it('Mentions of payment in policy are not flagged as demands', () => {
    const text = 'Our policy is that we do not accept any payment from candidates. In the past, fraudsters have demanded fees in our name. Report such attempts to police.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    const findings = analyzeChunk(chunks[0]);
    
    if (findings.paymentSignals.hasPaymentRequest) {
      assert.strictEqual(findings.paymentSignals.hasPaymentNegation, true);
    }
  });

  it('Company policy document mentioning salary structure is not flagged as fee', () => {
    const text = 'Compensation Structure: Basic Salary Rs 40,000/month. HRA: Rs 12,000. Total CTC: Rs 6,24,000 per annum. No caution money is required.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    const findings = analyzeChunk(chunks[0]);
    
    assert.ok(findings.paymentSignals.hasPaymentNegation || !findings.paymentSignals.hasPaymentRequest);
  });
});

describe('Chunk Analysis: Entity Extraction', () => {
  it('Extracts emails correctly', () => {
    const text = 'Contact us at hr@company.com or support@company.co.in for any queries.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    const findings = analyzeChunk(chunks[0]);
    
    assert.ok(findings.entities.emails.includes('hr@company.com'));
    assert.ok(findings.entities.emails.includes('support@company.co.in'));
  });

  it('Extracts UPI IDs as suspicious signals', () => {
    const text = 'Pay via UPI to abcpayment@paytm for confirming your slot.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    const findings = analyzeChunk(chunks[0]);
    
    assert.ok(findings.entities.upiIds.length > 0);
    assert.ok(findings.suspiciousPatterns.includes('UPI_ID_IN_OFFER'));
  });

  it('Extracts CIN numbers correctly', () => {
    const text = 'Our Company Identification Number is L22210MH1995PLC084781, registered with MCA.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    const findings = analyzeChunk(chunks[0]);
    
    assert.ok(findings.entities.cinNumbers.includes('L22210MH1995PLC084781'));
  });
});

describe('Chunking: Semantic Section Classification', () => {
  it('Payment section is classified as PAYMENT_TERMS', () => {
    const text = 'Please pay the registration fee of Rs 3500 via bank transfer.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    
    assert.strictEqual(chunks[0].section, 'PAYMENT_TERMS');
  });

  it('Compensation section is classified as COMPENSATION', () => {
    const text = 'Your CTC will be Rs 8,00,000 per annum with a basic salary of Rs 5,00,000.';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    
    assert.strictEqual(chunks[0].section, 'COMPENSATION');
  });

  it('Signature section is classified correctly', () => {
    const text = 'Authorized Signatory\nHR Manager\nTata Consultancy Services';
    const chunks = chunkDocument(text, 'DOC-TEST', {});
    
    assert.strictEqual(chunks[0].section, 'SIGNATURE');
  });

  it('Each chunk has a unique chunkId and hash', () => {
    const text = `Dear Candidate,\n\nWe are pleased to offer you the position of Software Engineer.\n\nYour compensation will be Rs 8,00,000 per annum.\n\nPlease note that no registration fee is required.\n\nRegards,\nHR Team`;
    const chunks = chunkDocument(text, 'DOC-001', {});
    
    const chunkIds = chunks.map(c => c.chunkId);
    const hashes = chunks.map(c => c.hash);
    
    assert.strictEqual(new Set(chunkIds).size, chunkIds.length);
    assert.strictEqual(new Set(hashes).size, hashes.length);
  });

  it('Same text always produces same chunk IDs and hashes (determinism)', () => {
    const text = 'Dear Candidate, we are pleased to offer you the position.\n\nYour salary will be Rs 5,00,000 per annum.';
    
    const chunks1 = chunkDocument(text, 'DOC-001', {});
    const chunks2 = chunkDocument(text, 'DOC-001', {});
    
    assert.strictEqual(chunks1.length, chunks2.length);
    chunks1.forEach((c, i) => {
      assert.strictEqual(c.chunkId, chunks2[i].chunkId);
      assert.strictEqual(c.hash, chunks2[i].hash);
      assert.strictEqual(c.section, chunks2[i].section);
    });
  });
});

describe('Required Regression Suite: Fee-Demand Detection and Context Classification', () => {
  it('Detects target sentence: "To CONFIRM your enrolment, you are required to pay rsxxx" as EXPLICIT_DEMAND', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('To CONFIRM your enrolment, you are required to pay rsxxx');
    assert.strictEqual(res.has_fee_demand, true);
    assert.strictEqual(res.payment_case, 'EXPLICIT_DEMAND');
    assert.ok(res.fee_details?.[0]?.exact_quote.includes('To CONFIRM your enrolment'));
  });

  it('Detects target sentence split across OCR/PDF line breaks as EXPLICIT_DEMAND', async () => {
    const { extractDocumentSignals, splitTextIntoSentences } = await import('../services/documentService');
    const text = 'To CONFIRM your enrolment,\nyou are required to pay rsxxx';
    const sents = splitTextIntoSentences(text);
    assert.ok(sents.length >= 1);
    const res = extractDocumentSignals(text);
    assert.strictEqual(res.has_fee_demand, true);
    assert.strictEqual(res.payment_case, 'EXPLICIT_DEMAND');
  });

  it('Detects target sentence variant: "To confirm your enrollment, you must pay Rs. 5,000" as EXPLICIT_DEMAND', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('To confirm your enrollment, you must pay Rs. 5,000');
    assert.strictEqual(res.has_fee_demand, true);
    assert.strictEqual(res.payment_case, 'EXPLICIT_DEMAND');
  });

  it('Detects target sentence with trailing currency token: "To CONFIRM your enrolment, you are required to pay rs" as EXPLICIT_DEMAND', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('To CONFIRM your enrolment, you are required to pay rs');
    assert.strictEqual(res.has_fee_demand, true);
    assert.strictEqual(res.payment_case, 'EXPLICIT_DEMAND');
    assert.ok(res.fee_details?.[0]?.exact_quote.includes('To CONFIRM your enrolment'));
  });

  it('Classifies genuine candidate stipend without payment demand as NO_PAYMENT_EVIDENCE or POLICY', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('Your monthly stipend will be Rs. 15,000 per month.');
    assert.strictEqual(res.has_fee_demand, false);
    assert.notStrictEqual(res.payment_case, 'EXPLICIT_DEMAND');
    assert.notStrictEqual(res.payment_case, 'CONDITIONAL_DEMAND');
  });

  it('Classifies genuine annual salary without payment demand as NO_PAYMENT_EVIDENCE or POLICY', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('Your annual salary is Rs. 5,00,000 per annum payable monthly.');
    assert.strictEqual(res.has_fee_demand, false);
    assert.notStrictEqual(res.payment_case, 'EXPLICIT_DEMAND');
  });

  it('Classifies explicit fee negation "No registration fee is required from candidates" as NO payment demand', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('No registration fee is required from candidates. Application is free.');
    assert.strictEqual(res.has_fee_demand, false);
    assert.notStrictEqual(res.payment_case, 'EXPLICIT_DEMAND');
  });

  it('Classifies explicit anti-scam warning "Applicants are warned never to pay recruitment fees" as WARNING_AGAINST_PAYMENT', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('Applicants are warned never to pay recruitment fees to anyone. We never charge money.');
    assert.strictEqual(res.has_fee_demand, false);
    assert.strictEqual(res.payment_case, 'WARNING_AGAINST_PAYMENT');
  });

  it('Classifies corporate expense reimbursement "The company reimburses training expenses" as POLICY_MENTION_WITHOUT_DEMAND', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('The company reimburses training expenses incurred during the probationary period.');
    assert.strictEqual(res.has_fee_demand, false);
    assert.strictEqual(res.payment_case, 'POLICY_MENTION_WITHOUT_DEMAND');
  });

  it('Preserves CONDITIONAL_DEMAND for refundable deposit statement', async () => {
    const { extractDocumentSignals } = await import('../services/documentService');
    const res = extractDocumentSignals('A refundable deposit must be paid before joining, refundable upon completion of tenure.');
    assert.strictEqual(res.has_fee_demand, true);
    assert.strictEqual(res.payment_case, 'CONDITIONAL_DEMAND');
  });

  it('Ensures confirmed payment demand triggers PAYMENT_REQUEST_CAP and critical risk in scoringService', async () => {
    const { calculateDeterministicScore } = await import('../services/scoringService');
    const score = calculateDeterministicScore({
      documentData: {
        payment_case: 'EXPLICIT_DEMAND',
        has_fee_demand: true,
        fee_details: [{
          category: 'UPFRONT_FEE_DEMAND',
          exact_quote: 'To CONFIRM your enrolment, you are required to pay rs',
          why_it_matters: 'Fee demand',
          confidence: 96,
        }],
      } as any,
    });
    assert.ok(score.trust_score <= 20, `Expected trust score <= 20, got ${score.trust_score}`);
    assert.ok(score.hard_caps_applied.some(c => c.includes('PAYMENT_REQUEST_CAP')));
    const fin = score.assessments?.find(a => a.id === 'financial_safety');
    assert.strictEqual(fin?.risk_band, 'CRITICAL_RISK');
    assert.ok((fin?.risk_score || 0) >= 76);
  });

  it('Ensures negative payment case (e.g. WARNING_AGAINST_PAYMENT) does NOT trigger PAYMENT_REQUEST_CAP even if legacy fee_details is present', async () => {
    const { calculateDeterministicScore } = await import('../services/scoringService');
    const score = calculateDeterministicScore({
      documentData: {
        payment_case: 'WARNING_AGAINST_PAYMENT',
        has_fee_demand: false,
        fee_details: [{
          category: 'UPFRONT_FEE_DEMAND',
          exact_quote: 'Stale quote',
          confidence: 50,
        }],
      } as any,
    });
    assert.ok(!score.hard_caps_applied.some(c => c.includes('PAYMENT_REQUEST_CAP')));
    const fin = score.assessments?.find(a => a.id === 'financial_safety');
    assert.notStrictEqual(fin?.risk_band, 'CRITICAL_RISK');
  });
});
