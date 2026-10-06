import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateClaimInvestigationQueue } from '../services/huggingfaceService';
import { validateAssertion, validateAssertionScope, guardFindingsList, runReportAssertionGuard } from '../services/reportAssertionGuard';
import { extractDocumentSignals } from '../services/documentService';
import { detectVisualRegions, determineSignatoryState } from '../services/visualForensicsService';

describe('Hugging Face Claim Investigation Queue', () => {
  it('generates dynamic investigation queries directly from extracted offer claims', () => {
    const queue = generateClaimInvestigationQueue([], {
      companyName: 'ABC Technologies Pvt Ltd',
      domain: 'abc-technologies-careers.com',
      recruiterEmail: 'rahul.hr@gmail.com',
      recruiterName: 'Rahul Kumar',
      role: 'Software Engineer Intern',
      stipend: 'INR 25,000 per month',
      paymentAmount: '3500',
      upiId: 'abctech@okhdfcbank',
    });

    assert.ok(queue.totalClaims >= 5, 'Queue should contain claim items for company, recruiter, email, role, and fee');
    assert.strictEqual(queue.companyName, 'ABC Technologies Pvt Ltd');

    // Verify company claim queries
    const compClaim = queue.items.find(i => i.claimType === 'COMPANY_IDENTITY');
    assert.ok(compClaim, 'Company claim must exist');
    assert.ok(compClaim.queries.some(q => q.includes('"ABC Technologies Pvt Ltd" official website')));
    assert.ok(compClaim.queries.some(q => q.includes('careers "Software Engineer Intern"')));

    // Verify recruiter claim queries
    const recClaim = queue.items.find(i => i.claimType === 'RECRUITER_IDENTITY');
    assert.ok(recClaim, 'Recruiter claim must exist');
    assert.ok(recClaim.queries.some(q => q.includes('"Rahul Kumar" "ABC Technologies Pvt Ltd"')));

    // Verify email claim queries
    const emlClaim = queue.items.find(i => i.claimType === 'COMMUNICATION_CHANNEL');
    assert.ok(emlClaim, 'Email claim must exist');
    assert.ok(emlClaim.queries.some(q => q.includes('"rahul.hr@gmail.com"')));

    // Verify financial demand claim queries (critical)
    const feeClaim = queue.items.find(i => i.claimType === 'FINANCIAL_TRANSACTION_SAFETY');
    assert.ok(feeClaim, 'Fee demand claim must exist');
    assert.ok(feeClaim.queries.some(q => q.includes('"abctech@okhdfcbank" scam complaint fraud')));

    // Ensure no generic static queries like "known fake companies" exist
    assert.ok(!queue.allQueries.some(q => q.includes('known fake companies')));
  });
});

describe('Report Assertion Guard', () => {
  const registeredIds = new Set([
    'EXT-MCA21-7F92A',
    'Doc-P1-C01',
    'Ext-NEWS-01',
    'EXT-CIN-99B1A',
  ]);

  it('allows statements with valid evidence citations', () => {
    const res1 = validateAssertion('An active corporate record was confirmed in the registry. [EXT-MCA21-7F92A]', registeredIds);
    assert.strictEqual(res1.isAllowed, true);
    assert.strictEqual(res1.hasEvidenceCitation, true);
    assert.strictEqual(res1.citationFound, '[EXT-MCA21-7F92A]');

    const res2 = validateAssertion('Document header declares formal appointment. [Doc-P1-C01]', registeredIds);
    assert.strictEqual(res2.isAllowed, true);
    assert.strictEqual(res2.hasEvidenceCitation, true);
  });

  it('allows statements that explicitly declare epistemic uncertainty or non-findings', () => {
    const res1 = validateAssertion('No matching corporate record was located in the searched registry. This does not imply fraud.', registeredIds);
    assert.strictEqual(res1.isAllowed, true);
    assert.strictEqual(res1.isExplicitUncertainty, true);

    const res2 = validateAssertion('Recruiter identity could not be confirmed in public professional records.', registeredIds);
    assert.strictEqual(res2.isAllowed, true);
    assert.strictEqual(res2.isExplicitUncertainty, true);
  });

  it('blocks or flags unsupported positive assertions lacking evidence and uncertainty framing', () => {
    const res = validateAssertion('The recruiter has 12 years of enterprise hiring experience in Bangalore.', registeredIds);
    assert.strictEqual(res.isAllowed, false);
    assert.strictEqual(res.hasEvidenceCitation, false);
    assert.strictEqual(res.isExplicitUncertainty, false);
  });

  it('sanitizes findings lists by converting unsupported factual claims to honest unverified statements', () => {
    const findings = [
      'Document structure consistent with legitimate offer. [Doc-P1-C01]',
      'Company employs 500+ engineers in Whitefield.', // Unsupported factual claim
      'Candidate payment requirement could not be confirmed in the letter.', // Explicit uncertainty
    ];

    const { sanitizedList, audit } = guardFindingsList(findings, registeredIds);
    assert.strictEqual(audit.checked, 3);
    assert.strictEqual(audit.allowed, 2);
    assert.strictEqual(audit.sanitized, 1);
    assert.ok(sanitizedList[1].includes('Statement could not be verified against collected evidence'));
  });

  it('audits full scan reports comprehensively', () => {
    const mockReport = {
      trust_score: 85,
      verdict: 'LIKELY_GENUINE',
      risk_level: 'LOW',
      critical_signals: [],
      warning_signals: ['Isolated negative review found. [Ext-NEWS-01]'],
      positive_signals: ['Company registered in MCA21. [EXT-MCA21-7F92A]'],
      dual_rag_citations: {
        document_citations: [{ citation: 'Doc-P1-C01' }],
        external_citations: [{ citation: 'Ext-NEWS-01' }],
      },
    };

    const { guardedReport, guardAudit } = runReportAssertionGuard(mockReport, [
      { id: 'EXT-MCA21-7F92A' },
      { id: 'Ext-NEWS-01' },
      { id: 'Doc-P1-C01' },
    ]);

    assert.ok(guardedReport.assertion_guard_audit, 'Audit object must be attached');
    assert.strictEqual(guardAudit.totalAssertionsChecked, 2);
    assert.strictEqual(guardAudit.allowedWithEvidence, 2);
    assert.strictEqual(guardAudit.blockedOrSanitized, 0);
  });
});

describe('Document Service: Raw vs Normalized Evidence', () => {
  it('extracts structured normalized evidence while preserving raw OCR', () => {
    const sampleText = `
      TATA MOTORS LIMITED
      OFFER OF INTERNSHIP
      
      Dear Sanjay Kumar,
      We are pleased to offer you the position of Software Engineer Intern at Tata Motors Limited.
      Your monthly stipend will be Rs. 25,000 per month.
      Your date of joining is 15th October 2026.
      Please contact our HR team at careers@tatamotors.com.
      
      Authorized Signatory: Rajesh Sharma, Head of Talent Acquisition
    `;

    const rawOcr = sampleText.toUpperCase(); // simulate raw noisy OCR
    const signals = extractDocumentSignals(sampleText, 'offer.pdf', 'application/pdf', rawOcr, 'PSZEMRAJ_DOCTR');

    assert.ok(signals.normalized_evidence, 'normalized_evidence must be created');
    assert.strictEqual(signals.normalized_evidence.candidate_name, 'Sanjay Kumar');
    assert.strictEqual(signals.normalized_evidence.company_name, 'TATA MOTORS LIMITED');
    assert.strictEqual(signals.normalized_evidence.recruiter_email, 'careers@tatamotors.com');
    assert.strictEqual(signals.normalized_evidence.ocr_engine, 'PSZEMRAJ_DOCTR');
    assert.strictEqual(signals.raw_ocr, rawOcr, 'Raw OCR must be preserved unaltered');
    assert.ok(signals.normalized_evidence.selection_statement?.toLowerCase().includes('offer'));
  });
});

describe('Visual Forensics & Signatory Service', () => {
  it('identifies visual signature blocks via text pattern fallback', async () => {
    const text = 'We look forward to working with you.\n\nYours sincerely,\nE. Sai Reddy\nHead - Talent Acquisition\nAcme Technologies Solutions';
    const result = await detectVisualRegions(Buffer.from([]), 'text/plain', 'SCAN-TEST-001', text);

    assert.ok(result.regions.length > 0, 'Should detect at least one visual/signatory region');
    assert.strictEqual(result.signatureType, 'VISUAL_SIGNATURE');
    assert.strictEqual(result.signatoryState, 'SIGNATORY_OBSERVED');
    assert.strictEqual(result.signatoryName, 'E. Sai Reddy');
    assert.strictEqual(result.signatoryTitle, 'Head - Talent Acquisition');
  });

  it('generates scan-scoped evidence IDs without cross-scan collision', async () => {
    const scanId1 = 'SCAN-AAA-111';
    const scanId2 = 'SCAN-BBB-222';
    const text = 'Authorized Signatory\nJohn Doe\nDirector';

    const res1 = await detectVisualRegions(Buffer.from([]), 'text/plain', scanId1, text);
    const res2 = await detectVisualRegions(Buffer.from([]), 'text/plain', scanId2, text);

    assert.ok(res1.evidence[0].id.startsWith(scanId1), 'Evidence ID must be prefixed with scanId1');
    assert.ok(res2.evidence[0].id.startsWith(scanId2), 'Evidence ID must be prefixed with scanId2');
    assert.notStrictEqual(res1.evidence[0].id, res2.evidence[0].id, 'Evidence IDs must not collide');
  });

  it('strictly treats signature presence as OBSERVED and NEVER verified (no trust boost)', async () => {
    const text = 'Sincerely,\nRobert Smith\nHR Manager';
    const result = await detectVisualRegions(Buffer.from([]), 'text/plain', 'SCAN-TRUST-CHECK', text);

    for (const ev of result.evidence) {
      assert.strictEqual(ev.verified, false, 'Visual observation must NOT have verified: true');
      assert.strictEqual(ev.status, 'UNKNOWN', 'Visual observation status must be UNKNOWN');
      assert.strictEqual(ev.severity, 'INFO', 'Visual observation severity must be INFO');
    }
  });

  it('differentiates VISUAL_SIGNATURE from CRYPTOGRAPHIC_SIGNATURE', async () => {
    const text = 'Regards,\nAuthorized Signatory\nPriya Sharma';
    const result = await detectVisualRegions(Buffer.from([]), 'text/plain', 'SCAN-SIG-TYPE', text);

    assert.strictEqual(result.signatureType, 'VISUAL_SIGNATURE');
    assert.notStrictEqual(result.signatureType, 'CRYPTOGRAPHIC_SIGNATURE', 'Must not claim cryptographic signature from visual layout');
  });

  it('correctly transitions signatory verification states', () => {
    assert.strictEqual(determineSignatoryState([]), 'NO_SIGNATURE_DETECTED');
    assert.strictEqual(determineSignatoryState([{ type: 'SIGNATURE', page: 1, confidence: 0.8, detectionMethod: 'TEXT_PATTERN', evidenceId: 'E1' }]), 'SIGNATURE_PRESENT_UNIDENTIFIED');
    assert.strictEqual(determineSignatoryState([{ type: 'SIGNATURE', page: 1, confidence: 0.8, detectionMethod: 'TEXT_PATTERN', evidenceId: 'E2' }], 'Jane Doe'), 'SIGNATORY_OBSERVED');
  });
});

describe('Report Assertion Guard Semantic Scope Check', () => {
  it('blocks and replaces false negative HR claims when visual signature evidence exists', () => {
    const evidenceItems = [
      { id: 'SCAN-001-DOC-P1-SIG-A1B2', evidence_type: 'VISUAL_SIGNATURE', title: 'Visual Signature Observed', status: 'UNKNOWN' }
    ];
    const validIds = new Set(['SCAN-001-DOC-P1-SIG-A1B2']);

    const badStatement = 'No HR contact person name identified in letter.';
    const result = validateAssertion(badStatement, validIds, evidenceItems);

    assert.strictEqual(result.isAllowed, true);
    assert.ok(!result.text.includes('No HR contact person name identified'), 'Statement must be replaced');
    assert.ok(result.text.includes('visual signature was observed'), 'Must state visual signature was observed');
    assert.ok(result.text.includes('unverified against internal corporate signatory roll'), 'Must clarify unverified state');
  });

  it('prevents false unregistered company assertions when local reference exists', () => {
    const evidenceItems = [
      { id: 'EXT-MCA-001', evidence_type: 'LOCAL_REFERENCE_FOUND', title: 'Local Reference Match: Infosys Ltd' }
    ];
    const validIds = new Set(['EXT-MCA-001']);

    const statement = 'The entity is an unregistered company.';
    const result = validateAssertion(statement, validIds, evidenceItems);

    assert.strictEqual(result.isAllowed, true);
    assert.ok(result.text.includes('Entity documented in local corporate reference dataset'));
  });
});

describe('Document Service: Absence of Signatory Is Not Fraud', () => {
  it('flags missing signatory as info advisory rather than severity high red flag', () => {
    const sampleText = 'Welcome to the organization. This document outlines your terms of employment. General terms apply across all departments for new joiners. Please review carefully and report on date specified.';
    const signals = extractDocumentSignals(sampleText);

    const highPersonFlags = signals.triggered_flags.filter(f => f.rule === 'ner_person' && f.severity === 'high');
    assert.strictEqual(highPersonFlags.length, 0, 'Must NOT trigger severity: high ner_person fraud flag');

    const advisory = signals.triggered_flags.find(f => f.rule === 'doc_signatory_advisory');
    if (advisory) {
      assert.strictEqual(advisory.severity, 'info', 'Advisory must have severity: info');
    }
  });
});

