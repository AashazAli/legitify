// ==============================================================================
// LEGITIFY STRUCTURE COMPLIANCE & SIGNATORY FORENSICS TEST SUITE
// Evidence-based testing for Document Authenticity, Semantic Structure,
// and Visual/Signatory Forensics across Cases A through J.
// ==============================================================================

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDocumentStructureAndFormat } from '../../lib/forensics/AnalysisEngine';
import { inspectPdfCryptographicSignature } from '../utils/pdfSignature';
import { detectVisualRegions, determineSignatoryState } from '../services/visualForensicsService';
import { calculateDeterministicScore, ScoringInputs } from '../services/scoringService';
import { DocumentExtractionResult } from '../services/documentService';

describe('PDF Cryptographic Signature Inspection', () => {
  it('returns hasEmbeddedSignature: false for non-PDF buffers', () => {
    const textBuffer = Buffer.from('Digitally signed by HR Manager on 2026-10-23');
    const result = inspectPdfCryptographicSignature(textBuffer);
    assert.strictEqual(result.hasEmbeddedSignature, false);
    assert.strictEqual(result.isCryptographicVerified, false);
    assert.strictEqual(result.signatureFormat, 'NONE');
  });

  it('returns hasEmbeddedSignature: false for plain PDF without signature dictionaries', () => {
    const plainPdfBuffer = Buffer.from(
      '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' +
      '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n' +
      '3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\nxref\n0 4\ntrailer\n<< /Root 1 0 R >>\n%%EOF'
    );
    const result = inspectPdfCryptographicSignature(plainPdfBuffer);
    assert.strictEqual(result.hasEmbeddedSignature, false);
    assert.strictEqual(result.isCryptographicVerified, false);
    assert.strictEqual(result.signatureFormat, 'NONE');
  });

  it('does not falsely classify "Digitally Signed" plain text inside PDF as cryptographic', () => {
    const textPdfBuffer = Buffer.from(
      '%PDF-1.4\n' +
      'BT /F1 12 Tf (This offer letter is digitally signed by Director) Tj ET\n' +
      '%%EOF'
    );
    const result = inspectPdfCryptographicSignature(textPdfBuffer);
    assert.strictEqual(result.hasEmbeddedSignature, false);
    assert.strictEqual(result.isCryptographicVerified, false);
    assert.strictEqual(result.signatureFormat, 'NONE');
  });

  it('detects genuine PDF cryptographic signature dictionary with ByteRange and Sig type', () => {
    const signedPdfBuffer = Buffer.from(
      '%PDF-1.7\n' +
      '4 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ' +
      '/ByteRange [0 1000 2000 3000] /Contents <3082046206092a864886f70d010702> >>\nendobj\n' +
      '%%EOF'
    );
    const result = inspectPdfCryptographicSignature(signedPdfBuffer);
    assert.strictEqual(result.hasEmbeddedSignature, true);
    assert.strictEqual(result.signatureFormat, 'CRYPTOGRAPHIC_PKCS7');
    assert.strictEqual(result.subFilter, 'adbe.pkcs7.detached');
  });
});

describe('Signatory & Visual Forensics Isolation & Title Extraction', () => {
  it('correctly extracts signatory name and Founder title from inline text format', async () => {
    const rawText =
      'Nexus Technologies Pvt Ltd\n' +
      'Offer of Employment\n' +
      'Dear Rajesh Kumar,\n' +
      'We are pleased to offer you the position of Software Engineer.\n\n' +
      'Sincerely,\n' +
      'Sudip Das — Founder\n' +
      'Nexus Technologies';

    const result = await detectVisualRegions(
      Buffer.from('%PDF-1.4\n%%EOF'),
      'application/pdf',
      'TEST-SCAN-1',
      rawText
    );

    assert.strictEqual(result.signatoryName, 'Sudip Das');
    assert.strictEqual(result.signatoryTitle, 'Founder');
    assert.strictEqual(result.hasSignatoryBlock, true);
    assert.strictEqual(result.signatoryState, 'SIGNATORY_OBSERVED');
    assert.notStrictEqual(result.signatoryTitle, 'Human Resources & Talent Acquisition');
    assert.notStrictEqual(result.signatureType, 'ABSENT');
  });

  it('preserves printed signatory block when no visual mark is present', async () => {
    const rawText =
      'Acme Global Solutions\n' +
      'To: Priyanshu Sharma\n' +
      'Role: Cloud Architect\n' +
      'Monthly Compensation: Rs. 95,000\n\n' +
      'Authorized Signatory\n' +
      'Anita Roy\n' +
      'Head of Human Resources';

    const result = await detectVisualRegions(
      Buffer.from('%PDF-1.4\n%%EOF'),
      'application/pdf',
      'TEST-SCAN-2',
      rawText
    );

    assert.strictEqual(result.hasSignatoryBlock, true);
    assert.strictEqual(result.signatoryName, 'Anita Roy');
    assert.strictEqual(result.signatoryTitle, 'Head of Human Resources');
    assert.strictEqual(result.signatoryState, 'SIGNATORY_OBSERVED');
    assert.strictEqual(result.signatureType, 'PRINTED_SIGNATORY');
  });

  it('marks identity as SIGNATURE_PRESENT_UNIDENTIFIED when visual mark is present but OCR fails to read name', () => {
    const state = determineSignatoryState(
      [{ type: 'SIGNATURE', page: 1, confidence: 0.9, detectionMethod: 'GEMINI_VISION' } as any],
      undefined,
      false,
      true
    );

    assert.strictEqual(state, 'SIGNATURE_PRESENT_UNIDENTIFIED');
  });

  it('marks identity as SIGNATORY_BLOCK_OBSERVED when department block exists without individual name', async () => {
    const rawText =
      'Starlight Infotech\n' +
      'Internship Offer\n' +
      'Role: Data Science Intern\n' +
      'Sincerely,\n' +
      'Human Resources Department\n' +
      'Starlight Infotech Pvt Ltd';

    const result = await detectVisualRegions(
      Buffer.from('%PDF-1.4\n%%EOF'),
      'application/pdf',
      'TEST-SCAN-3',
      rawText
    );

    assert.strictEqual(result.hasSignatoryBlock, true);
    assert.strictEqual(result.signatoryState, 'SIGNATORY_BLOCK_OBSERVED');
    assert.strictEqual(result.signatureType, 'SIGNATORY_BLOCK');
    assert.strictEqual(result.hasVisualSignatureMark, false);
  });

  it('reports ABSENT and NO_SIGNATURE_DETECTED only when document genuinely has no signature or signatory block', async () => {
    const rawText = 'Just a casual message without any signoff or company representative.';

    const result = await detectVisualRegions(
      Buffer.from('%PDF-1.4\n%%EOF'),
      'application/pdf',
      'TEST-SCAN-4',
      rawText
    );

    assert.strictEqual(result.signatureType, 'ABSENT');
    assert.strictEqual(result.signatoryState, 'NO_SIGNATURE_DETECTED');
    assert.strictEqual(result.hasSignatoryBlock, false);
    assert.strictEqual(result.hasVisualSignatureMark, false);
  });
});

describe('Document Authenticity & Semantic Structure Compliance (Cases A through J)', () => {

  it('Case A: Complete genuine offer letter satisfies all core semantic criteria without spurious penalties', () => {
    const rawText =
      'INFOSYS LIMITED\n' +
      'Electronics City, Hosur Road, Bangalore 560100\n' +
      'Date: October 20, 2026\n' +
      'Ref No: HR/OFFER/2026/8941\n\n' +
      'Dear Ananya Sharma,\n' +
      'Sub: Offer of Employment\n\n' +
      'We are pleased to offer you the position of Senior Systems Engineer at Infosys Limited.\n' +
      'Your annual CTC will be Rs. 9,50,000 per annum with full benefits.\n' +
      'Your expected date of joining is November 15, 2026 at our Bangalore office.\n\n' +
      'Sincerely,\n' +
      'For Infosys Limited,\n' +
      'Sudip Das — Founder & Managing Director\n' +
      'Human Resources Department';

    const result = analyzeDocumentStructureAndFormat(rawText, 'INFOSYS LIMITED');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 80, `Expected structureScore >= 80, received ${result.structureScore}`);
    assert.ok(result.passedChecksCount >= 7, `Expected at least 7 passed checks, got ${result.passedChecksCount}`);
    assert.strictEqual(result.hasSignatoryIdentity, true);
    assert.strictEqual(result.signatoryName, 'Sudip Das');
    assert.strictEqual(result.signatoryTitle, 'Founder & Managing Director');
    assert.strictEqual(result.missingElements.length, 0);
  });

  it('Case B: Minimal modern offer letter passes without formal letterhead, postal address, or ref number', () => {
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
    assert.ok(result.structureScore >= 70, `Expected structureScore >= 70 for modern offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Sarah Jenkins');
    assert.strictEqual(result.signatoryTitle, 'Head of Engineering Talent');
  });

  it('Case C: Internship appointment letter passes with stipend, duration, and supervisor context', () => {
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
    assert.ok(result.structureScore >= 70, `Expected structureScore >= 70 for internship offer, got ${result.structureScore}`);
    assert.strictEqual(result.hasAuthorizedSignatoryBlock, true);
  });

  it('Case D: Email-based / plain-text offer evaluated on semantic content rather than visual styling', () => {
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
    assert.ok(result.structureScore >= 70, `Expected structureScore >= 70 for email offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Meera Sen');
  });

  it('Case E: Printed signatory without visual mark reports signatory block and title without fabricating HR fallback', () => {
    const rawText =
      'Apex FinTech Solutions\n' +
      'October 22, 2026\n\n' +
      'Dear Neha,\n' +
      'We offer you the role of Risk Analyst with an annual package of Rs. 8,00,000.\n' +
      'Reporting date: November 25, 2026.\n\n' +
      'Sincerely,\n' +
      'Ramesh Iyer — Chief Executive Officer\n' +
      'Apex FinTech Solutions';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Apex FinTech Solutions');

    assert.strictEqual(result.hasSignatoryIdentity, true);
    assert.strictEqual(result.signatoryName, 'Ramesh Iyer');
    assert.strictEqual(result.signatoryTitle, 'Chief Executive Officer');
    assert.notStrictEqual(result.signatoryTitle, 'Human Resources & Talent Acquisition');
  });

  it('Case F: Visual signature with OCR-failed signatory text reports visual mark without inventing placeholder name', () => {
    const rawText =
      'Vertex Heavy Industries Ltd\n' +
      'Date: October 12, 2026\n\n' +
      'Dear Amit,\n' +
      'Offer of Employment for the position of Mechanical Engineer.\n' +
      'Salary: Rs. 6,50,000 per annum. Joining: December 1, 2026.\n\n' +
      '[Signature Image Present Below]';

    const result = analyzeDocumentStructureAndFormat(rawText, 'Vertex Heavy Industries Ltd');

    assert.strictEqual(result.hasVisualSignatureMark, true);
    assert.strictEqual(result.signatoryName, undefined);
  });

  it('Case G: Formal signature block without mark attributes identity to department/role', () => {
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
    const signCheck = result.structureChecks.find(c => c.id === 'SEM-07');
    assert.ok(signCheck);
    assert.strictEqual(signCheck.passed, true);
  });

  it('Case H: Poor scan / uncertainty reports gracefully without excessive penalty', () => {
    const rawText =
      '..ex Tech..gies\n' +
      'Offer.. Emp..yment\n' +
      'De..r S..mith,\n' +
      'Posi..on: Dev..oper\n' +
      'Stipend: Rs. 20,000\n' +
      'Date: 2026-10-22';

    const result = analyzeDocumentStructureAndFormat(rawText);

    // Score reflects extraction limitation without treating it as malicious forged structure
    assert.ok(result.structureScore >= 30, `Expected structureScore >= 30, got ${result.structureScore}`);
    assert.ok(result.missingElements.length > 0);
  });

  it('Case I: Diverse legitimate document structure (table-based terms, two-column layout)', () => {
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
  });

  it('Case J: Multi-page offer letter evaluates criteria across all pages', () => {
    const page1 =
      'TATA CONSULTANCY SERVICES LIMITED\n' +
      'TCS House, Raveline Street, Fort, Mumbai 400001\n' +
      'Date: October 20, 2026\n' +
      'Dear Karthik Subramanian,\n' +
      'Sub: Letter of Offer - TCS Digital\n' +
      'We have pleasure in offering you employment in the role of Digital Technology Specialist.';

    const page2 =
      'ANNEXURE A: TERMS & COMPENSATION\n' +
      'Your annual Total Gross CTC will be INR 7,50,000.\n' +
      'Your initial reporting date is November 20, 2026 at TCS Siruseri, Chennai.';

    const page3 =
      'ANNEXURE B: ACCEPTANCE & SIGN-OFF\n' +
      'Please sign and return the duplicate copy of this letter.\n\n' +
      'Yours sincerely,\n' +
      'For Tata Consultancy Services Limited,\n' +
      'Deepak Sharma\n' +
      'Global Head - Talent Acquisition';

    const fullMultiPageText = `${page1}\n\n--- Page Break ---\n\n${page2}\n\n--- Page Break ---\n\n${page3}`;

    const result = analyzeDocumentStructureAndFormat(fullMultiPageText, 'Tata Consultancy Services Limited');

    assert.strictEqual(result.status, 'STANDARD_COMPLIANT');
    assert.ok(result.structureScore >= 80, `Expected structureScore >= 80 for 3-page offer, got ${result.structureScore}`);
    assert.strictEqual(result.signatoryName, 'Deepak Sharma');
    assert.strictEqual(result.signatoryTitle, 'Global Head - Talent Acquisition');
  });
});

describe('Decoupling Structure Analysis from Unrelated Assessments', () => {

  it('document structure score is not contaminated by fee demands or payment requests', () => {
    const rawCleanText =
      'Vortex Solutions Pvt Ltd\n' +
      'October 21, 2026\n\n' +
      'Dear Sunita,\n' +
      'We offer you the role of QA Tester with a salary of Rs. 50,000 per month.\n' +
      'Start Date: November 15, 2026.\n\n' +
      'Sincerely,\n' +
      'Sunil Verma — HR Director';

    const rawTextWithFeeDemand =
      rawCleanText + '\n\nTo CONFIRM your enrolment, you are required to pay Rs. 2,500 security deposit.';

    const cleanResult = analyzeDocumentStructureAndFormat(rawCleanText, 'Vortex Solutions Pvt Ltd');
    const feeResult = analyzeDocumentStructureAndFormat(rawTextWithFeeDemand, 'Vortex Solutions Pvt Ltd');

    // Structure score must evaluate the structural criteria without deducting structure points for fee demands
    // (Fee demand is evaluated strictly by the Financial Fee Safety dimension)
    assert.strictEqual(feeResult.structureScore, cleanResult.structureScore);
    assert.strictEqual(feeResult.status, cleanResult.status);
  });

  it('scoring engine generates Low Risk (<= 10) for Assessment 3 when document structure is verified', () => {
    const mockExtraction: DocumentExtractionResult = {
      is_offer_letter: true,
      has_official_letterhead: true,
      has_candidate_name: true,
      has_role_details: true,
      has_salary_details: true,
      has_joining_date: true,
      has_authorized_signatory: true,
      has_contact_info: true,
      has_terms_and_conditions: true,
      has_company_cin: false,
      detected_signatory: 'Sudip Das',
      detected_signatory_title: 'Founder',
      has_signatory_block: true,
      missing_fields: [],
      advisory_warnings: ['Corporate CIN or ROC identifier not printed on letterhead'],
      raw_text: 'Legitimate complete offer letter text...',
      text_length: 1200
    };

    const inputs: ScoringInputs = {
      documentData: mockExtraction,
      companyData: {
        is_registered: true,
        company_status: 'Active',
        company_name: 'Nexus Technologies Pvt Ltd',
        source_verified: true,
        cin: 'U72200KA2020PTC123456',
        incorporation_date: '2020-01-15'
      } as any,
      domainData: {
        domain: 'nexustechnologies.com',
        domain_exists: true,
        domain_age_days: 1200,
        is_free_provider: false
      } as any,
      recruiterData: {
        email: 'hr@nexustechnologies.com',
        domain: 'nexustechnologies.com',
        is_free_provider: false,
        is_disposable: false
      } as any
    };

    const scoringResult = calculateDeterministicScore(inputs);
    const docAssessment = scoringResult.assessments.find(a => a.id === 'document_authenticity');

    assert.ok(docAssessment, 'Expected document_authenticity assessment item');
    assert.ok(
      docAssessment.risk_score <= 10,
      `Expected document authenticity risk <= 10 for verified structure, received ${docAssessment.risk_score}`
    );
    assert.strictEqual(docAssessment.risk_band, 'LOW_RISK');
  });
});
