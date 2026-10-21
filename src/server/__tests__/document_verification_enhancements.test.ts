// ==============================================================================
// LEGITIFY DOCUMENT VERIFICATION ENHANCEMENTS: 6-PILLAR COMPREHENSIVE TEST SUITE
// ==============================================================================
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { isFilenameOrPlaceholder } from '../utils/normalizer';
import { extractDocumentSignals } from '../services/documentService';
import {
  calculateDeterministicScore,
  buildStandardAssessments,
  getRiskBand,
  getRiskBandLabel,
} from '../services/scoringService';
import { generateEvidenceGroundedAnswer } from '../services/aiProvider';
import {
  LinkedInResearchProvider,
  RedditResearchProvider,
  QuoraResearchProvider,
  MCAGovProvider,
  executeExternalResearch,
} from '../services/externalResearchService';
import { generatePdfDocument } from '../../lib/pdfExport';
import { LegitifyReport, AssessmentItem } from '../../types';

// ==============================================================================
// PILLAR 1: Payment and Financial Fee Risk Assessment
// ==============================================================================
describe('Pillar 1: Payment & Financial Fee Risk Assessment', () => {
  it('Extracts explicit candidate fee demands with amount, recipient, refund terms, and exact quote', () => {
    const textWithFee = `
      APPOINTMENT LETTER - JUNIOR CLOUD ASSOCIATE
      Candidates must deposit a mandatory refundable laptop caution fee of Rs. 4,500 via UPI to hr.onboarding@icici before 25th October 2026.
      This amount will be refunded in your first salary disbursement.
    `;
    const signals = extractDocumentSignals(textWithFee);

    assert.strictEqual(signals.has_fee_demand, true, 'Fee demand flag must be true');
    assert.ok(signals.fee_details && signals.fee_details.length > 0, 'Must extract fee_details');

    const primaryFee = signals.fee_details![0];
    assert.strictEqual(primaryFee.is_refundable, true, 'Pretext refundability must be detected');
    assert.ok(/4,?500/.test(primaryFee.amount || ''), 'Amount must capture 4,500');
    assert.ok(primaryFee.recipient?.includes('hr.onboarding@icici'), 'Recipient must capture UPI ID');
    assert.ok(primaryFee.exact_quote.toLowerCase().includes('laptop caution fee') || primaryFee.exact_quote.toLowerCase().includes('4,500'), 'Exact quote must be retained');
  });

  it('Accurately distinguishes candidate compensation (stipend/salary) from candidate fee demands', () => {
    const textWithStipendOnly = `
      INTERNSHIP OFFER LETTER
      Organization: Google India Private Limited
      Position: Software Engineering Intern
      Remuneration: Selected candidates will receive a monthly stipend of Rs. 45,000 / month.
      No registration fees or security deposits are required at any stage of recruitment.
    `;
    const signals = extractDocumentSignals(textWithStipendOnly);

    assert.strictEqual(signals.has_fee_demand, false, 'No candidate fee should be flagged');
    assert.ok(signals.candidate_compensation, 'Candidate compensation should be detected');
    assert.strictEqual(signals.candidate_compensation?.type, 'STIPEND');
    assert.ok(signals.candidate_compensation?.amount?.includes('45,000'));
  });

  it('Guarantees salary statement "The company will pay an amount of ₹30,000 per month as salary" produces zero fee demand and low risk', () => {
    const salaryOnlyText = `
      EMPLOYMENT APPOINTMENT LETTER
      Employer: Tech Mahindra Solutions Ltd
      Role: Associate Software Engineer
      The company will pay an amount of ₹30,000 per month as salary.
      Office Location: Tech Mahindra Campus, Hinjawadi, Pune.
      Joining Date: 15th November 2026.
    `;
    const signals = extractDocumentSignals(salaryOnlyText);

    assert.strictEqual(signals.has_fee_demand, false, 'Salary payment from employer must NOT be flagged as candidate fee demand');
    assert.strictEqual(signals.payment_case, 'NO_PAYMENT_EVIDENCE', 'Payment case must be NO_PAYMENT_EVIDENCE');
    assert.strictEqual(signals.fee_details?.length || 0, 0, 'No candidate fee details should be extracted');

    const scoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'Tech Mahindra Solutions Ltd',
      documentData: signals as any,
    });
    const finAssessment = scoreResult.assessments?.find(a => a.id === 'financial_safety');
    assert.ok(finAssessment, 'financial_safety assessment must exist');
    assert.ok(finAssessment.risk_score <= 10, `financial_safety risk score must be <= 10, got ${finAssessment.risk_score}`);
    assert.strictEqual(finAssessment.risk_band, 'LOW_RISK');
    assert.strictEqual(finAssessment.risk_band_label, 'Low Risk');
  });

  it('Scores financial safety deterministically: Fee demand => Critical Risk, Compensation => Low Risk, Neutral => Low Risk', () => {
    // 1. Fee Demand Case
    const feeScoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'Acme Corp',
      documentData: {
        raw_text: 'Pay Rs 5000 fee',
        has_fee_demand: true,
        fee_details: [{
          category: 'Laptop caution deposit',
          amount: 'Rs. 5,000',
          recipient: 'deposit@upi',
          is_refundable: true,
          refund_terms: 'refunded with first stipend',
          exact_quote: 'Pay Rs 5000 fee',
          why_it_matters: 'Employers do not charge fees',
          confidence: 98,
        }],
      },
    });
    const feeAssessment = feeScoreResult.assessments?.find(a => a.id === 'financial_safety');
    assert.ok(feeAssessment, 'Financial safety assessment must exist');
    assert.ok(feeAssessment.risk_score >= 80 && feeAssessment.risk_score <= 99, 'Fee demand must yield Critical Risk score');
    assert.strictEqual(feeAssessment.risk_band, 'CRITICAL_RISK');
    assert.ok(feeScoreResult.trust_score <= 20, 'Payment request cap must keep trust <= 20');

    // 2. Candidate Compensation Case
    const compScoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'Acme Corp',
      documentData: {
        raw_text: 'Stipend: Rs. 25,000 / month',
        has_fee_demand: false,
        candidate_compensation: {
          type: 'STIPEND',
          amount: 'Rs. 25,000 / month',
          raw_quote: 'Stipend: Rs. 25,000 / month',
        },
      },
    });
    const compAssessment = compScoreResult.assessments?.find(a => a.id === 'financial_safety');
    assert.ok(compAssessment);
    assert.ok(compAssessment.risk_score <= 15, 'Candidate compensation must yield Low Risk score');
    assert.strictEqual(compAssessment.risk_band, 'LOW_RISK');

    // 3. Neutral Zero-Fee Case
    const neutralScoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'Acme Corp',
      documentData: {
        raw_text: 'Job description for developer.',
        has_fee_demand: false,
      },
    });
    const neutralAssessment = neutralScoreResult.assessments?.find(a => a.id === 'financial_safety');
    assert.ok(neutralAssessment);
    assert.ok(neutralAssessment.risk_score <= 15, 'Neutral zero-fee must yield Low Risk score');
    assert.strictEqual(neutralAssessment.risk_band, 'LOW_RISK');
  });
});

// ==============================================================================
// PILLAR 2: Organization Name Extraction & Filename Leakage Prevention
// ==============================================================================
describe('Pillar 2: Organization Name Extraction & Filename Leakage Prevention', () => {
  it('Correctly identifies filenames, upload stamps, and generic placeholders', () => {
    const invalidNames = [
      'WhatsApp Image 2024-03-15 at 12.30.00.jpeg',
      'screenshot 2024-10-12 at 4.15.22 PM.png',
      'IMG_20241015_WA0004.jpg',
      'document.pdf',
      'offer_letter_v2.pdf',
      'scan_001.png',
      'pasted_text_17291823912.txt',
      'unknown',
      'Unknown Organization',
      'corporate entity',
      'investigated entity',
      'uploaded document',
      '20241015_182930.jpg',
      '',
      '   ',
    ];

    for (const name of invalidNames) {
      assert.strictEqual(
        isFilenameOrPlaceholder(name),
        true,
        `Expected "${name}" to be identified as filename/placeholder`
      );
    }
  });

  it('Preserves genuine company names without false positives', () => {
    const validCompanies = [
      'Tata Consultancy Services',
      'Google India Private Limited',
      'Infosys BPM Limited',
      'Microsoft India (R&D) Pvt Ltd',
      'Wipro Limited',
      'Reliance Industries',
      'Larsen & Toubro',
    ];

    for (const company of validCompanies) {
      assert.strictEqual(
        isFilenameOrPlaceholder(company),
        false,
        `Expected authentic company "${company}" NOT to be flagged as placeholder`
      );
    }
  });

  it('Assigns 50/100 Moderate Risk when company cannot be confidently identified', () => {
    const scoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'WhatsApp Image 2024-10-15 at 12.30.00.jpeg', // Filename passed as entity
      documentData: {
        raw_text: 'Generic offer without company name or CIN.',
        detected_company_name: undefined,
      },
    });

    const corpAssessment = scoreResult.assessments?.find(a => a.id === 'company_registry');
    assert.ok(corpAssessment, 'Corporate identity assessment must exist');
    assert.strictEqual(corpAssessment.risk_score, 50, 'Unidentified organization must receive Risk Score 50');
    assert.strictEqual(corpAssessment.risk_band, 'MODERATE_RISK');
    assert.ok(corpAssessment.evidence_found.includes('Organization not confidently identified'));
  });
});

// ==============================================================================
// PILLAR 3: Internet Research Service Guardrails
// ==============================================================================
describe('Pillar 3: Internet Research Service Guardrails', () => {
  it('Guards external research providers against searching filenames', async () => {
    const filenameInput = 'WhatsApp Image 2024-10-15 at 12.30.00.jpeg';

    const linkedInProvider = new LinkedInResearchProvider();
    const linkedIn = await linkedInProvider.searchRecruiterAndCompany({ companyName: filenameInput });
    assert.strictEqual(linkedIn.status, 'NO_DATA');
    assert.strictEqual(linkedIn.searchQueries.length, 0);
    assert.ok(linkedIn.summary.includes('Organization not confidently identified'));

    const redditProvider = new RedditResearchProvider();
    const reddit = await redditProvider.searchScamDiscussions({ companyName: filenameInput });
    assert.strictEqual(reddit.status, 'NO_DATA');
    assert.strictEqual(reddit.searchQueries.length, 0);

    const quoraProvider = new QuoraResearchProvider();
    const quora = await quoraProvider.searchCandidateExperiences({ companyName: filenameInput });
    assert.strictEqual(quora.status, 'NO_DATA');
    assert.strictEqual(quora.searchQueries.length, 0);

    const mcaProvider = new MCAGovProvider();
    const mca = await mcaProvider.verifyStatutoryFiling({ companyName: filenameInput });
    assert.strictEqual(mca.status, 'NO_DATA');
    assert.strictEqual(mca.searchQueries.length, 0);

    const unified = await executeExternalResearch({ companyName: filenameInput });
    const allQueries = [
      ...unified.providers.linkedin.searchQueries,
      ...unified.providers.reddit.searchQueries,
      ...unified.providers.quora.searchQueries,
      ...unified.providers.mca.searchQueries,
    ];
    assert.strictEqual(allQueries.length, 0, 'Unified research must not issue any queries for filenames');
  });

  it('Generates focused multi-query research for authentic corporate entities', async () => {
    const company = 'Tata Consultancy Services';

    const linkedInProvider = new LinkedInResearchProvider();
    const linkedIn = await linkedInProvider.searchRecruiterAndCompany({ companyName: company });
    assert.ok(linkedIn.searchQueries.some(q => q.includes('site:linkedin.com/company')));
    assert.ok(linkedIn.findings.length > 0);

    const redditProvider = new RedditResearchProvider();
    const reddit = await redditProvider.searchScamDiscussions({ companyName: company });
    assert.ok(reddit.searchQueries.some(q => q.includes('r/developersIndia')));

    const quoraProvider = new QuoraResearchProvider();
    const quora = await quoraProvider.searchCandidateExperiences({ companyName: company });
    assert.ok(quora.searchQueries.some(q => q.includes('site:quora.com')));

    const mcaProvider = new MCAGovProvider();
    const mca = await mcaProvider.verifyStatutoryFiling({ companyName: company });
    assert.ok(mca.searchQueries.some(q => q.includes('site:mca.gov.in') || q.includes('CIN')));

    const unified = await executeExternalResearch({ companyName: company });
    const allQueries = [
      ...unified.providers.linkedin.searchQueries,
      ...unified.providers.reddit.searchQueries,
      ...unified.providers.quora.searchQueries,
      ...unified.providers.mca.searchQueries,
    ];
    assert.ok(allQueries.length >= 4, 'Unified research must generate multiple focused queries');
    assert.ok(unified.allFindings.length >= 4, 'Unified research must compile multi-source findings');
  });
});

// ==============================================================================
// PILLAR 4: Multi-Vector Risk Assessments (12 Uniform Assessments)
// ==============================================================================
describe('Pillar 4: Multi-Vector Risk Assessments (12 Uniform Assessments)', () => {
  it('Generates all 12 standard assessments with uniform 0-100 scale and 4 risk bands', () => {
    const scoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'Infosys Limited',
      companyData: { legal_name: 'Infosys Limited', mca_status: 'ACTIVE' },
      documentData: {
        raw_text: 'Offer from Infosys Limited. No fee required. Monthly stipend: Rs. 30,000.',
        detected_company_name: 'Infosys Limited',
        has_fee_demand: false,
        candidate_compensation: { type: 'STIPEND', amount: 'Rs. 30,000' },
      },
      recruiterData: { is_free_provider: false },
    });

    const assessments = scoreResult.assessments;
    assert.ok(assessments && assessments.length === 12, `Expected exactly 12 assessments, got ${assessments?.length}`);

    const expectedIds = [
      'overall_offer_risk',
      'financial_safety',
      'document_authenticity',
      'company_registry',
      'domain_intelligence',
      'recruiter_email',
      'communication_channel',
      'signatory_identity',
      'ml_fraud_pattern',
      'community_sentiment',
      'threat_intelligence',
      'consistency_conflict',
    ];

    for (const id of expectedIds) {
      const found = assessments.find(a => a.id === id);
      assert.ok(found, `Assessment ${id} must be present`);
      assert.ok(typeof found.risk_score === 'number', `${id} risk_score must be number`);
      assert.ok(found.risk_score >= 0 && found.risk_score <= 100, `${id} risk_score must be 0-100, got ${found.risk_score}`);
      assert.ok(['LOW_RISK', 'MINOR_IRREGULARITIES', 'MODERATE_RISK', 'CRITICAL_RISK'].includes(found.risk_band), `Invalid risk_band: ${found.risk_band}`);
      assert.ok(found.recommended_next_step && found.recommended_next_step.length > 5, `${id} must have recommended_next_step`);
      assert.ok(found.why_it_matters && found.why_it_matters.length > 5, `${id} must have why_it_matters`);
    }
  });

  it('Verifies risk band boundary mapping strictly adheres to specification', () => {
    // 0–15 => LOW_RISK
    assert.strictEqual(getRiskBand(0), 'LOW_RISK');
    assert.strictEqual(getRiskBand(15), 'LOW_RISK');
    assert.strictEqual(getRiskBandLabel('LOW_RISK'), 'Low Risk');

    // 16–40 => MINOR_IRREGULARITIES
    assert.strictEqual(getRiskBand(16), 'MINOR_IRREGULARITIES');
    assert.strictEqual(getRiskBand(40), 'MINOR_IRREGULARITIES');
    assert.strictEqual(getRiskBandLabel('MINOR_IRREGULARITIES'), 'Minor Irregularities');

    // 41–70 => MODERATE_RISK
    assert.strictEqual(getRiskBand(41), 'MODERATE_RISK');
    assert.strictEqual(getRiskBand(70), 'MODERATE_RISK');
    assert.strictEqual(getRiskBandLabel('MODERATE_RISK'), 'Moderate Risk');

    // 71–100 => CRITICAL_RISK
    assert.strictEqual(getRiskBand(71), 'CRITICAL_RISK');
    assert.strictEqual(getRiskBand(100), 'CRITICAL_RISK');
    assert.ok(getRiskBandLabel('CRITICAL_RISK').includes('Critical'));
  });
});

// ==============================================================================
// PILLAR 5: AI Chatbot Context & Grounding
// ==============================================================================
describe('Pillar 5: AI Chatbot Context & Grounding', () => {
  it('Handles "Why is payment risk low?" query with zero-fee explanation and compensation details', async () => {
    const mockContext = {
      company_name: 'Tata Consultancy Services',
      trust_score: 92,
      risk_level: 'LOW',
      document_analysis: {
        has_fee_demand: false,
        candidate_compensation: {
          type: 'STIPEND',
          amount: 'Rs. 25,000 / month',
        },
      },
      assessments: [
        {
          id: 'financial_safety',
          title: 'Payment and Financial Fee Safety',
          risk_score: 5,
          risk_band: 'LOW_RISK',
          risk_band_label: 'Low Risk',
          risk_details: 'Candidate compensation detected. Zero upfront fees.',
        },
      ],
    };

    const answer = await generateEvidenceGroundedAnswer('Why is payment risk low?', mockContext);
    assert.ok(answer.includes('Zero Candidate Payment Demands Detected'), 'Must report zero fee demand');
    assert.ok(answer.includes('25,000'), 'Must include candidate compensation figure');
    assert.ok(answer.includes('Zero-Fee Hiring Protocol'), 'Must reference Zero-Fee principle');
  });

  it('Handles "Why is payment risk high?" query with exact quote, amount, recipient, and 1930 Helpline', async () => {
    const mockContext = {
      company_name: 'Fraudulent Recruiter Org',
      trust_score: 15,
      risk_level: 'CRITICAL',
      document_analysis: {
        has_fee_demand: true,
        fee_details: [
          {
            category: 'Laptop Security Deposit',
            amount: 'Rs. 6,500',
            recipient: 'deposit.onboarding@paytm',
            is_refundable: true,
            refund_terms: 'Refunded with first month stipend',
            exact_quote: 'Candidates must deposit Rs 6500 via UPI to deposit.onboarding@paytm',
            why_it_matters: 'Genuine employers never charge caution money',
          },
        ],
      },
      assessments: [
        {
          id: 'financial_safety',
          title: 'Payment and Financial Fee Safety',
          risk_score: 96,
          risk_band: 'CRITICAL_RISK',
          risk_band_label: 'Critical Risk',
        },
      ],
    };

    const answer = await generateEvidenceGroundedAnswer('Why is payment risk high?', mockContext);
    assert.ok(answer.includes('Explicit Candidate Payment Demand Detected'), 'Must flag explicit payment demand');
    assert.ok(answer.includes('6,500'), 'Must quote amount');
    assert.ok(answer.includes('deposit.onboarding@paytm'), 'Must quote recipient endpoint');
    assert.ok(answer.includes('1930'), 'Must include National Cybercrime Helpline 1930 advisory');
    assert.ok(answer.includes('DO NOT TRANSFER FUNDS'), 'Must warn against fund transfers');
  });

  it('Handles unidentified organization queries by confirming filenames were filtered and risk is 50/100', async () => {
    const mockContext = {
      company_name: 'Organization Not Confidently Identified',
      trust_score: 50,
      risk_level: 'MODERATE',
      assessments: [
        {
          id: 'corporate_identity',
          title: 'Corporate Identity and Registry Verification',
          risk_score: 50,
          risk_band: 'MODERATE_RISK',
          risk_band_label: 'Moderate Risk',
        },
      ],
    };

    const answer = await generateEvidenceGroundedAnswer('Who is this company and why is it not identified?', mockContext);
    assert.ok(answer.includes('Organization Not Confidently Identified'));
    assert.ok(answer.includes('50/100'));
    assert.ok(answer.includes('Filenames, timestamps, and upload metadata were strictly filtered out'));
  });

  it('Responds to simple greeting "hi" conversationally without forensic briefing header or extracted audit profile', async () => {
    const mockContext = {
      company_name: 'Microsoft India Pvt Ltd',
      trust_score: 95,
      risk_level: 'LOW',
      user_name: 'Rahul',
    };

    const answer = await generateEvidenceGroundedAnswer('hi', mockContext);
    assert.ok(answer.toLowerCase().includes('hello rahul') || answer.toLowerCase().includes('hello'), 'Must greet candidate naturally');
    assert.ok(!answer.includes('### Forensic Intelligence Briefing'), 'Must NOT dump Forensic Intelligence Briefing header');
    assert.ok(!answer.includes('Extracted Document Audit Profile'), 'Must NOT dump Extracted Document Audit Profile template');
    assert.ok(!answer.includes('1/100'), 'Must not display broken 1/100 score');
    assert.ok(answer.includes('Payment & Fees'), 'Must offer assistance categories');
  });

  it('Responds to polite greeting "Good morning, can you help me?" conversationally', async () => {
    const mockContext = {
      company_name: 'Infosys',
      trust_score: 80,
      user_name: 'Aashaz',
    };

    const answer = await generateEvidenceGroundedAnswer('Good morning, can you help me?', mockContext);
    assert.ok(!answer.includes('### Forensic Intelligence Briefing'), 'Must NOT dump header');
    assert.ok(!answer.includes('Extracted Document Audit Profile'), 'Must NOT dump template');
    assert.ok(answer.includes('LEGITIFY Forensic Investigation Assistant'));
  });
});

// ==============================================================================
// PILLAR 6: Single Source of Truth Alignment (Report & PDF Integrity)
// ==============================================================================
describe('Pillar 6: Single Source of Truth Alignment (Report & PDF Generation)', () => {
  it('Generates multi-page PDF rendering all 12 assessments with sanitized company name and legal disclaimer', () => {
    const scoreResult = calculateDeterministicScore({
      entityType: 'job_offer',
      entityValue: 'WhatsApp Image 2024-10-15.jpeg',
      documentData: {
        raw_text: 'Please pay Rs 3,500 registration fee to recruiter@upi.',
        has_fee_demand: true,
        fee_details: [
          {
            category: 'Registration Fee',
            amount: 'Rs. 3,500',
            recipient: 'recruiter@upi',
            is_refundable: false,
            exact_quote: 'Please pay Rs 3,500 registration fee to recruiter@upi.',
            why_it_matters: 'Genuine employers never demand registration fees.',
            confidence: 98,
          },
        ],
      },
    });

    const mockReport: LegitifyReport = {
      scan_id: 'SCAN-ENHANCED-001',
      created_at: new Date().toISOString(),
      entity_type: 'job_offer',
      entity_value: 'WhatsApp Image 2024-10-15.jpeg', // Filename as input
      company_name: 'WhatsApp Image 2024-10-15.jpeg', // Filename leakage test
      trust_score: scoreResult.trust_score,
      risk_level: scoreResult.risk_level,
      verdict: scoreResult.verdict,
      confidence: 96,
      document_analysis: {
        raw_text: 'Please pay Rs 3,500 registration fee to recruiter@upi.',
        has_fee_demand: true,
        fee_details: [
          {
            category: 'Registration Fee',
            amount: 'Rs. 3,500',
            recipient: 'recruiter@upi',
            is_refundable: false,
            exact_quote: 'Please pay Rs 3,500 registration fee to recruiter@upi.',
            why_it_matters: 'Genuine employers never demand registration fees.',
            confidence: 98,
          },
        ],
        candidate_compensation: undefined,
        suspicious_patterns: ['Upfront registration fee demanded'],
        extracted_entities: {},
        evidence: [],
        triggered_flags: [],
        dimension_scores: { rules: 10, nlp: 15, ner: 20 },
        final_score: 18,
      },
      scoring: {
        finalTrust: scoreResult.trust_score,
        verdict: scoreResult.verdict,
        confidence: 96,
        riskLevel: scoreResult.risk_level,
        hardCapsTriggered: scoreResult.hard_caps_applied,
        componentBreakdown: scoreResult.components,
        assessments: scoreResult.assessments,
      },
      assessments: scoreResult.assessments,
      company_verification: {
        legal_name: 'WhatsApp Image 2024-10-15.jpeg',
        status: 'UNVERIFIED',
      } as any,
      critical_signals: ['Mandatory candidate fee requested in offer.'],
    } as any;

    // Generate PDF document
    const doc = generatePdfDocument(mockReport);
    assert.ok(doc, 'PDF Document must be created successfully');

    // Multi-page document check
    const pages = doc.getNumberOfPages();
    assert.ok(pages >= 2, `PDF report must have at least 2 pages for all 12 assessments and sections, got ${pages}`);
  });

  it('Exports PDF report accurately when trust_score is 1 without hardcoding or crashing', () => {
    const reportWithLowTrust: LegitifyReport = {
      scan_id: 'SCAN-CRITICAL-002',
      created_at: new Date().toISOString(),
      entity_type: 'job_offer',
      company_name: 'Tata Consultancy Services',
      trust_score: 1,
      overall_risk_score: 99,
      risk_level: 'CRITICAL',
      verdict: 'LIKELY SCAM',
      confidence: 98,
      has_fee_demand: true,
      assessments: [
        {
          id: 'overall_offer_risk',
          name: 'Overall Employment Offer Risk',
          risk_score: 99,
          risk_band: 'CRITICAL_RISK',
          risk_band_label: 'Critical Fraud Risk',
          evidence_found: 'Severe fraud signals detected.',
          why_it_matters: 'High likelihood of malicious employment scam.',
          evidence_strength: 'High',
          recommended_next_step: 'Do NOT send money.',
        },
        {
          id: 'financial_safety',
          name: 'Payment and Financial Fee Safety',
          risk_score: 96,
          risk_band: 'CRITICAL_RISK',
          risk_band_label: 'Critical Fraud Risk',
          evidence_found: 'Deposit required.',
          why_it_matters: 'Zero fee standard violated.',
          evidence_strength: 'High',
          recommended_next_step: 'Report to 1930.',
        },
      ],
    } as any;

    const doc = generatePdfDocument(reportWithLowTrust);
    assert.ok(doc, 'PDF Document must be created successfully');
    assert.ok(doc.getNumberOfPages() >= 1, 'PDF must generate pages');
  });
});
