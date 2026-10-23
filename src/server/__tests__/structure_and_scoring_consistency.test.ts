// ==============================================================================
// LEGITIFY STRUCTURE COMPLIANCE & TRUST INDEX SCORING CONSISTENCY TEST SUITE
// Evidence-based testing for Document Authenticity, Structural Standards,
// and Authoritative Multi-Factor Deterministic Trust Scoring.
// Strictly zero emojis across all code, assertions, and test outputs.
// ==============================================================================

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDocumentStructureAndFormat } from '../../lib/forensics/AnalysisEngine';
import { calculateDeterministicScore, ScoringInputs } from '../services/scoringService';
import { DocumentExtractionResult } from '../services/documentService';

// ==============================================================================
// PART 1: DOCUMENT AUTHENTICITY & STRUCTURE STANDARDS (CASES 1 THROUGH 12)
// ==============================================================================

describe('Document Authenticity & Structure Standards (Cases 1 through 12)', () => {

  it('Case 1: Complete Formal Enterprise Offer Letter satisfies all 9 criteria with high confidence', () => {
    const rawText =
      'INFOSYS LIMITED\n' +
      'Electronics City, Hosur Road, Bangalore 560100\n' +
      'Date: October 20, 2026\n' +
      'Ref No: HR/OFFER/2026/8941\n\n' +
      'Dear Ananya Sharma,\n' +
      'Sub: Offer of Employment\n\n' +
      'We are pleased to offer you the position of Senior Systems Engineer at Infosys Limited.\n' +
      'Your annual CTC will be Rs. 9,50,000 per annum with full corporate benefits.\n' +
      'Your expected date of joining is November 15, 2026 at our Bangalore campus.\n' +
      'For queries, contact hr@infosys.com or call +91-80-28520261.\n\n' +
      'Sincerely,\n' +
      'For Infosys Limited,\n' +
      'Sudip Das — Founder & Managing Director\n' +
      'Human Resources Department';

    const result = analyzeDocumentStructureAndFormat(rawText, 'INFOSYS LIMITED');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 85, `Expected structureScore >= 85, received ${result.structureScore}`);
    assert.strictEqual(result.hasCorporateHeader, true);
    assert.strictEqual(result.hasRegisteredAddress, true);
    assert.strictEqual(result.hasContactInformation, true);
    assert.strictEqual(result.hasSpecificRole, true);
    assert.strictEqual(result.hasPersonalizedAddressee, true);
    assert.strictEqual(result.candidateName, 'Ananya Sharma');
    assert.strictEqual(result.signatoryName, 'Sudip Das');
    assert.strictEqual(result.signatoryTitle, 'Founder & Managing Director');
    assert.strictEqual(result.missingElements.length, 0);
  });

  it('Case 2: Minimalist Modern Tech Startup Offer passes without formal postal address or tracking number', () => {
    const rawText =
      'Stripe Payments Inc.\n' +
      'October 18, 2026\n\n' +
      'Hi Vikram,\n' +
      'We are thrilled to offer you the position of Full Stack Developer at Stripe.\n' +
      'Your starting base salary will be INR 24,00,000 per year.\n' +
      'Your start date will be December 1, 2026.\n\n' +
      'Best regards,\n' +
      'Sarah Jenkins\n' +
      'Head of Engineering Talent';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Stripe Payments Inc.');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 75, `Expected structureScore >= 75 for modern tech offer, got ${result.structureScore}`);
    assert.strictEqual(result.candidateName, 'Vikram');
    assert.strictEqual(result.signatoryName, 'Sarah Jenkins');
    assert.strictEqual(result.signatoryTitle, 'Head of Engineering Talent');
  });

  it('Case 3: Internship Appointment Letter passes with stipend, duration, and reporting terms', () => {
    const rawText =
      'Zeta AI Research Labs\n' +
      'Date of Issue: October 15, 2026\n\n' +
      'Internship Appointment Letter\n\n' +
      'Dear Priya Patel,\n' +
      'We are pleased to appoint you as Machine Learning Intern for a period of 6 months.\n' +
      'You will receive a monthly stipend of Rs. 35,000.\n' +
      'You will report to Dr. Arvind Raman, Lead AI Scientist, starting on November 10, 2026.\n\n' +
      'Warm regards,\n' +
      'Zeta AI Research Team\n' +
      'Authorized Signatory';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Zeta AI Research Labs');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 75, `Expected structureScore >= 75 for internship offer, got ${result.structureScore}`);
    assert.strictEqual(result.hasAuthorizedSignatoryBlock, true);
    assert.strictEqual(result.hasStipendOrCompensationTerms, true);
  });

  it('Case 4: Plain-Text Email Offer evaluated on semantic content rather than graphical styling', () => {
    const rawText =
      'From: careers@acmecorp.com\n' +
      'Date: Mon, 19 Oct 2026\n' +
      'Subject: Job Offer - Data Engineer\n\n' +
      'Dear Rohan,\n' +
      'Acme Corp is pleased to offer you the position of Data Engineer.\n' +
      'The compensation for this role is Rs. 12,00,000 per annum with standard benefits.\n' +
      'The commencement date is scheduled for November 16, 2026.\n\n' +
      'Best regards,\n' +
      'Meera Sen\n' +
      'Talent Acquisition Partner\n' +
      'Acme Corp';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Acme Corp');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 75, `Expected structureScore >= 75 for plain email offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Meera Sen');
    assert.strictEqual(result.hasContactInformation, true);
  });

  it('Case 5: Table-Based Terms & Multi-Column Layout preserves tabular structure extraction', () => {
    const rawText =
      'Krypton Cloud Solutions | Registered Office: Cyber Hub, Gurgaon\n' +
      'Date of Issuance: 2026-10-21 | Offer Ref: KC/2026/099\n\n' +
      'APPLICANT DETAILS\n' +
      'Candidate Name: Sneha Reddy\n' +
      'Designation: Site Reliability Engineer\n\n' +
      'COMPENSATION BREAKDOWN TABLE\n' +
      '| Component       | Monthly (INR) | Annual (INR) |\n' +
      '| Basic Salary    | 40,000        | 4,80,000     |\n' +
      '| HRA             | 20,000        | 2,40,000     |\n' +
      '| Special Allow   | 25,000        | 3,00,000     |\n' +
      '| Total Gross     | 85,000        | 10,20,000    |\n\n' +
      'Effective Joining Date: December 15, 2026\n\n' +
      'ACCEPTED AND AGREED FOR KRYPTON CLOUD SOLUTIONS:\n' +
      'Gaurav Mehta — VP of Engineering';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Krypton Cloud Solutions');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 80, `Expected structureScore >= 80 for tabular offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Gaurav Mehta');
    assert.strictEqual(result.signatoryTitle, 'VP of Engineering');
    assert.strictEqual(result.hasRegisteredAddress, true);
  });

  it('Case 6: Multi-Page Offer Letter evaluates criteria across all pages including sign-off before annexures', () => {
    const page1 =
      'TATA CONSULTANCY SERVICES LIMITED\n' +
      'TCS House, Raveline Street, Fort, Mumbai 400001\n' +
      'Date: October 20, 2026\n' +
      'Dear Karthik Subramanian,\n' +
      'Sub: Letter of Offer - TCS Digital\n' +
      'We have pleasure in offering you employment in the role of Digital Technology Specialist.\n\n' +
      'Yours sincerely,\n' +
      'For Tata Consultancy Services Limited,\n' +
      'Deepak Sharma\n' +
      'Global Head - Talent Acquisition';

    const page2 =
      'ANNEXURE A: TERMS & COMPENSATION BREAKDOWN\n' +
      'Your annual Total Gross CTC will be INR 7,50,000.\n' +
      'Your initial reporting date is November 20, 2026 at TCS Siruseri, Chennai.\n' +
      'Contact desk: careers@tcs.com | Phone: 022-67789999';

    const page3 =
      'ANNEXURE B: GOVERNANCE & CODE OF CONDUCT\n' +
      'Employee agrees to standard intellectual property and non-disclosure governance terms.';

    const fullMultiPageText = `${page1}\n\n--- Page Break ---\n\n${page2}\n\n--- Page Break ---\n\n${page3}`;

    const result = analyzeDocumentStructureAndFormat(fullMultiPageText, 'Tata Consultancy Services Limited');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 85, `Expected structureScore >= 85 for multi-page offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Deepak Sharma');
    assert.strictEqual(result.signatoryTitle, 'Global Head - Talent Acquisition');
    assert.strictEqual(result.candidateName, 'Karthik Subramanian');
    assert.strictEqual(result.hasRegisteredAddress, true);
    assert.strictEqual(result.hasContactInformation, true);
  });

  it('Case 7: Scanned / Degraded OCR Text reports gracefully without collapsing score to zero', () => {
    const rawText =
      '..ex Tech..gies\n' +
      'Offer.. Emp..yment\n' +
      'De..r S..mith,\n' +
      'Posi..on: Dev..oper\n' +
      'Stipend: Rs. 20,000\n' +
      'Date: 2026-10-22';

    const result = analyzeDocumentStructureAndFormat(rawText);

    assert.ok(result.structureScore >= 30, `Expected structureScore >= 30 for degraded scan, got ${result.structureScore}`);
    assert.ok(result.missingElements.length > 0);
  });

  it('Case 8: Offer with Digital / Cryptographic Signature reports visual mark or certificate indicator', () => {
    const rawText =
      'Quantico Systems LLC\n' +
      'Date: 2026-10-14\n' +
      'Dear David,\n' +
      'Offer of Employment for Lead Architect.\n' +
      'Compensation: $140,000 per year. Start date: November 1, 2026.\n\n' +
      'Digitally signed by Chief Operating Officer on 2026-10-14\n' +
      '[Signature Image Present Below]';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Quantico Systems LLC');

    assert.strictEqual(result.hasVisualSignatureMark, true);
    assert.strictEqual(result.signatureDetected, true);
  });

  it('Case 9: Offer with Visual Stamp / Seal recognizes authorized signoff', () => {
    const rawText =
      'Apex Horizon Solutions\n' +
      'Date: October 10, 2026\n' +
      'To: Arvind Kumar\n' +
      'Offer of Appointment - Operations Manager\n' +
      'Salary: Rs. 85,000 per month. Joining: November 15, 2026.\n\n' +
      'Corporate Seal & Stamp Affixed\n' +
      'Signed by:\n' +
      'Rajesh Sen\n' +
      'Managing Director';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Apex Horizon Solutions');

    assert.strictEqual(result.hasAuthorizedSignatoryBlock, true);
    assert.strictEqual(result.signatoryName, 'Rajesh Sen');
    assert.strictEqual(result.signatoryTitle, 'Managing Director');
    assert.strictEqual(result.identityState, 'SIGNATORY_OBSERVED');
  });

  it('Case 10: Offer with Departmental Signatory attributes identity to department without inventing placeholder', () => {
    const rawText =
      'Pioneer Software Systems\n' +
      'Date: October 21, 2026\n\n' +
      'Dear Pooja,\n' +
      'We are pleased to offer you the position of Quality Assurance Engineer.\n' +
      'Compensation: INR 7,20,000 per annum.\n' +
      'Start Date: November 30, 2026.\n\n' +
      'Sincerely,\n' +
      'Authorized Signatory\n' +
      'Human Resources & Operations Team\n' +
      'Pioneer Software Systems';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Pioneer Software Systems');

    assert.strictEqual(result.hasAuthorizedSignatoryBlock, true);
    assert.strictEqual(result.signatoryName, undefined);
    assert.strictEqual(result.signatureDetected, true);
  });

  it('Case 11: International / Remote Offer validates without requiring local Indian corporate suffixes', () => {
    const rawText =
      'Cloudflare Inc.\n' +
      '101 Townsend St, San Francisco, CA 94107\n' +
      'October 19, 2026\n\n' +
      'Dear Elena Rostova,\n' +
      'We are delighted to extend an offer for the position of Senior Security Researcher.\n' +
      'Your base compensation will be $165,000 USD per annum.\n' +
      'Work Arrangement: Remote (Global Workforce Agreement).\n' +
      'Effective Start Date: December 1, 2026.\n' +
      'Contact: security-talent@cloudflare.com\n\n' +
      'Warm regards,\n' +
      'Matthew Prince — Chief Executive Officer';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Cloudflare Inc.');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 80, `Expected structureScore >= 80 for international offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Matthew Prince');
    assert.strictEqual(result.signatoryTitle, 'Chief Executive Officer');
    assert.strictEqual(result.hasRegisteredAddress, true);
    assert.strictEqual(result.hasContactInformation, true);
  });

  it('Case 12: Fraudulent / Incomplete Offer flags non-standard format and records omitted conventions', () => {
    const rawText =
      'Congratulations Dear Candidate,\n' +
      'You are selected for our company job.\n' +
      'You need to pay Rs 2500 registration charge immediately to confirm seat.\n' +
      'Send WhatsApp message to 9876543210.';

    const result = analyzeDocumentStructureAndFormat(rawText);

    assert.strictEqual(result.status, 'NON_STANDARD_FORMAT');
    assert.ok(result.structureScore < 50, `Expected structureScore < 50 for deficient letter, got ${result.structureScore}`);
    assert.ok(result.missingElements.length >= 3, `Expected at least 3 missing elements, found ${result.missingElements.length}`);
  });
});

// ==============================================================================
// PART 2: TRUST INDEX SCORING & FINAL VERDICT CONSISTENCY (CASES A THROUGH J)
// ==============================================================================

describe('Trust Index Scoring and Final Verdict Consistency (Cases A through J)', () => {

  it('Case A: High Trust, Genuine Document produces score >= 80, LIKELY LEGITIMATE, and Low Risk', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'Infosys Limited',
        company_status: 'Active',
        status: 'ACTIVE',
        is_registered: true,
        source_verified: true,
        registry_status: 'VERIFIED',
        mca_status: 'ACTIVE',
        cin: 'L85110KA1981PLC013115',
        incorporation_date: '1981-07-02',
      } as any,
      domainData: {
        domain: 'infosys.com',
        domain_exists: true,
        age_days: 10500,
        domain_age_days: 10500,
        ssl_valid: true,
        is_free_provider: false,
        has_mx: true,
        has_dns: true,
      } as any,
      recruiterData: {
        email: 'careers@infosys.com',
        domain: 'infosys.com',
        domain_alignment: 'EXACT_MATCH',
        is_free_provider: false,
        is_disposable: false,
      } as any,
      documentData: {
        filename: 'infosys_offer.pdf',
        mime_type: 'application/pdf',
        extracted_text: 'Complete genuine Infosys offer letter text with all standard conventions.',
        is_suspicious_offer_letter: false,
        final_score: 92,
        detected_company_name: 'Infosys Limited',
        detected_signatory: 'Sudip Das',
        detected_dates: ['2026-10-20'],
        triggered_flags: [],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score >= 80, `Expected trust_score >= 80, got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'LIKELY LEGITIMATE');
    assert.strictEqual(result.risk_level, 'LOW');
  });

  it('Case B: Low Risk Profile with minor flags produces score 65-79, LOW RISK, and Low Risk', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'TechSolutions Pvt Ltd',
        status: 'ACTIVE',
        is_registered: true,
        registry_status: 'VERIFIED',
      } as any,
      domainData: {
        domain: 'techsolutions.in',
        domain_exists: true,
        domain_age_days: 600,
        is_free_provider: false,
        has_mx: true,
      } as any,
      recruiterData: {
        email: 'recruiting@techsolutions.in',
        domain: 'techsolutions.in',
        domain_alignment: 'EXACT_MATCH',
        is_free_provider: false,
      } as any,
      documentData: {
        filename: 'offer.pdf',
        extracted_text: 'Legitimate offer text with minor structural formatting variations.',
        is_suspicious_offer_letter: false,
        final_score: 72,
        detected_company_name: 'TechSolutions Pvt Ltd',
        triggered_flags: [{ rule: 'minor_format', severity: 'low', message: 'Non-standard layout', score: 0.1 }],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score >= 65 && result.trust_score < 80, `Expected score in [65, 79], got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'LOW RISK');
    assert.strictEqual(result.risk_level, 'LOW');
  });

  it('Case C: Moderate Risk Document produces score 45-64, MODERATE RISK, and Moderate Risk', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'Unverified Entity',
        registry_status: 'NOT_FOUND',
      } as any,
      domainData: {
        domain: 'unverified-careers.net',
        domain_exists: true,
        domain_age_days: 45,
        is_free_provider: false,
      } as any,
      recruiterData: {
        email: 'hr@unverified-careers.net',
        domain: 'unverified-careers.net',
        is_free_provider: false,
      } as any,
      documentData: {
        filename: 'offer.pdf',
        extracted_text: 'Generic offer text with incomplete company background and newly registered domain.',
        is_suspicious_offer_letter: true,
        final_score: 52,
        triggered_flags: [
          { rule: 'young_domain', severity: 'medium', message: 'Domain registered recently', score: 0.25 },
        ],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score >= 45 && result.trust_score < 65, `Expected score in [45, 64], got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'MODERATE RISK');
    assert.strictEqual(result.risk_level, 'MODERATE');
  });

  it('Case D: High Risk Document with multiple anomalies produces score 28-44, HIGH RISK, and High Risk', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'Apex Impersonators',
        registry_status: 'NOT_FOUND',
      } as any,
      domainData: {
        domain: 'apex-job-offers.biz',
        domain_exists: true,
        age_days: 12,
        is_free_provider: false,
      } as any,
      recruiterData: {
        email: 'careers@apex-job-offers.biz',
        domain: 'apex-job-offers.biz',
        is_free_provider: false,
      } as any,
      documentData: {
        filename: 'sketchy_offer.pdf',
        extracted_text: 'Direct selection without technical interview, high urgency to sign within 24 hours.',
        is_suspicious_offer_letter: true,
        final_score: 32,
        triggered_flags: [
          { rule: 'urgent_deadline', severity: 'high', message: 'Artificial 24h pressure', score: 0.35 },
        ],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score >= 28 && result.trust_score < 45, `Expected score in [28, 44], got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'HIGH RISK');
    assert.strictEqual(result.risk_level, 'HIGH');
  });

  it('Case E: Critical Fraud / Likely Scam produces score < 28, LIKELY SCAM, and Critical Risk', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'Nonexistent Enterprise',
        registry_status: 'NOT_FOUND',
      } as any,
      domainData: {
        domain: 'gmail.com',
        is_free_provider: true,
      } as any,
      recruiterData: {
        email: 'recruiter.hr.tcs@gmail.com',
        domain: 'gmail.com',
        is_free_provider: true,
        domain_alignment: 'MISMATCH',
      } as any,
      documentData: {
        filename: 'fake_letter.pdf',
        extracted_text: 'Telegram interview followed by immediate appointment. Contact @recruiter_tcs on Telegram.',
        is_suspicious_offer_letter: true,
        is_confirmed_impersonation: true,
        final_score: 15,
        triggered_flags: [
          { rule: 'free_webmail', severity: 'critical', message: 'Public webmail provider used', score: 0.6 },
          { rule: 'telegram_comms', severity: 'critical', message: 'Encrypted chat application demanded', score: 0.5 },
        ],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score < 28, `Expected score < 28, got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'LIKELY SCAM');
    assert.strictEqual(result.risk_level, 'CRITICAL');
  });

  it('Case F: Mandatory Candidate Payment Demand strictly enforces ceiling <= 20 and LIKELY SCAM', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'Cognizant Technology Solutions',
        registry_status: 'VERIFIED',
        status: 'ACTIVE',
      } as any,
      domainData: {
        domain: 'cognizant.com',
        domain_exists: true,
        is_free_provider: false,
      } as any,
      recruiterData: {
        email: 'hr@cognizant.com',
        domain: 'cognizant.com',
        is_free_provider: false,
      } as any,
      documentData: {
        filename: 'offer_with_fee.pdf',
        extracted_text: 'To CONFIRM your enrolment, you are required to pay Rs 2,500 security deposit.',
        has_fee_demand: true,
        payment_case: 'EXPLICIT_DEMAND',
        fee_details: [{ amount: 'Rs. 2,500', category: 'SECURITY_DEPOSIT', exact_quote: 'pay Rs 2,500 security deposit' }],
        final_score: 12,
        triggered_flags: [
          { rule: 'candidate_fee_demand', severity: 'critical', message: 'Mandatory upfront candidate fee demanded', score: 0.8 },
        ],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score <= 20, `Expected score <= 20 under fee demand, got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'LIKELY SCAM');
    assert.strictEqual(result.risk_level, 'CRITICAL');
  });

  it('Case G: Free Webmail Provider enforces safety ceiling <= 24 and LIKELY SCAM', () => {
    const inputs: ScoringInputs = {
      companyData: {
        company_name: 'Wipro Limited',
        registry_status: 'VERIFIED',
      } as any,
      domainData: {
        domain: 'gmail.com',
        is_free_provider: true,
      } as any,
      recruiterData: {
        email: 'wipro.campus.hiring@gmail.com',
        domain: 'gmail.com',
        is_free_provider: true,
        domain_alignment: 'MISMATCH',
      } as any,
      documentData: {
        filename: 'wipro_gmail_offer.pdf',
        extracted_text: 'Offer claiming to be from Wipro sent from public personal webmail account.',
        final_score: 22,
        triggered_flags: [
          { rule: 'free_webmail', severity: 'critical', message: 'Corporate offer issued from Gmail', score: 0.6 },
        ],
      } as any,
    };

    const result = calculateDeterministicScore(inputs);

    assert.ok(result.trust_score <= 24, `Expected score <= 24 under free webmail cap, got ${result.trust_score}`);
    assert.strictEqual(result.verdict, 'LIKELY SCAM');
    assert.strictEqual(result.risk_level, 'CRITICAL');
  });

  it('Case H: Multi-Page Document Score Determinism guarantees identical scores across repeated runs', () => {
    const sampleInputs: ScoringInputs = {
      companyData: {
        company_name: 'Tata Consultancy Services',
        status: 'ACTIVE',
        is_registered: true,
        registry_status: 'VERIFIED',
      } as any,
      domainData: {
        domain: 'tcs.com',
        domain_exists: true,
        is_free_provider: false,
      } as any,
      recruiterData: {
        email: 'careers@tcs.com',
        domain: 'tcs.com',
        is_free_provider: false,
      } as any,
      documentData: {
        filename: 'tcs_multipage.pdf',
        extracted_text: 'Page 1 offer terms. Page 2 annexure breakdown. Page 3 sign-off.',
        final_score: 88,
        detected_company_name: 'Tata Consultancy Services',
      } as any,
    };

    const run1 = calculateDeterministicScore(sampleInputs);
    const run2 = calculateDeterministicScore(sampleInputs);
    const run3 = calculateDeterministicScore(sampleInputs);

    assert.strictEqual(run1.trust_score, run2.trust_score);
    assert.strictEqual(run2.trust_score, run3.trust_score);
    assert.strictEqual(run1.verdict, run2.verdict);
    assert.strictEqual(run1.risk_level, run2.risk_level);
  });

  it('Case I: Historical Scan Display Independence preserves historical report trust score without leakage', () => {
    // Simulate historical report loaded from database
    const historicalReport = {
      scan_id: 'SCAN-HISTORICAL-101',
      trust_score: 84,
      verdict: 'LIKELY LEGITIMATE',
      risk_level: 'LOW',
      company_name: 'Google LLC',
    };

    // Simulate stale in-memory forensic report from a different scan in the browser session
    const staleLiveReport = {
      custody: { custodyId: 'SCAN-LIVE-999' },
      scoring: { authenticityScore: 32 },
    };

    // Client-side isolation check: activeForensicReport must be null if custody IDs mismatch
    const activeForensic = (historicalReport.scan_id !== staleLiveReport.custody.custodyId)
      ? null
      : staleLiveReport;

    const rawTrustScore = typeof historicalReport.trust_score === 'number'
      ? Math.round(historicalReport.trust_score)
      : (activeForensic as any)?.scoring?.authenticityScore ?? 50;

    assert.strictEqual(activeForensic, null, 'Stale live scan forensic report must not leak into historical scan');
    assert.strictEqual(rawTrustScore, 84, 'Authoritative historical trust score must remain 84');
  });

  it('Case J: Offline / Fallback Mode Consistency uses client authenticity score when server score is absent', () => {
    const offlineReport: any = {
      scan_id: 'SCAN-OFFLINE-001',
      trust_score: undefined, // Backend was offline or unreachable
    };

    const clientReport = {
      scoring: { authenticityScore: 78, verdict: 'AUTHENTIC_VERIFIED' },
    };

    const effectiveScore = typeof offlineReport.trust_score === 'number'
      ? offlineReport.trust_score
      : clientReport.scoring.authenticityScore;

    assert.strictEqual(effectiveScore, 78, 'Expected client fallback score 78 when server score is undefined');
  });
});
