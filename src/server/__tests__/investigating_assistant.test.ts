import test from 'node:test';
import assert from 'node:assert/strict';
import { generateEvidenceGroundedAnswer, isDomainOffTopic, formatExternalResearchForPrompt, DOMAIN_GUARDRAIL_MESSAGE } from '../services/aiProvider';

// Helper to assert no emojis in response
function assertNoEmojis(text: string, contextDescription: string) {
  const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
  const match = text.match(emojiRegex);
  assert.equal(
    match,
    null,
    `Emoji detected in ${contextDescription}: "${match?.[0]}" in output:\n${text.substring(0, 100)}...`
  );
}

test('Scenario 1: Question answerable from document (stipend, role, working hours)', () => {
  const context = {
    company_name: 'Acme Technologies Pvt Ltd',
    trust_score: 85,
    document_analysis: {
      extracted_text: 'Offer of Internship. Role: Junior Machine Learning Engineer. Stipend: INR 25,000 per month. Working Hours: Monday to Friday 9:30 AM to 6:30 PM. Joining Date: 1st July 2026 at Bangalore Campus.',
      extracted_entities: {
        detected_company: 'Acme Technologies Pvt Ltd',
      },
    },
    extracted_offer_parts: {
      roles: ['Junior Machine Learning Engineer'],
      stipends: [{ rawText: 'INR 25,000 per month' }],
    },
  };

  // Test Role
  const roleAns = generateEvidenceGroundedAnswer('What role is offered in this document?', context);
  assert.match(roleAns, /Junior Machine Learning Engineer/i);
  assert.match(roleAns, /Acme Technologies/i);
  assertNoEmojis(roleAns, 'Role question');

  // Test Stipend
  const stipendAns = generateEvidenceGroundedAnswer('What is the stipend or salary for this position?', context);
  assert.match(stipendAns, /25,000/i);
  assertNoEmojis(stipendAns, 'Stipend question');

  // Test Working Hours
  const hoursAns = generateEvidenceGroundedAnswer('What are the working hours and shifts?', context);
  assert.match(hoursAns, /9:30 AM to 6:30 PM|Monday to Friday/i);
  assertNoEmojis(hoursAns, 'Hours question');

  // Test Joining Date
  const dateAns = generateEvidenceGroundedAnswer('When do I start or what is the joining date?', context);
  assert.match(dateAns, /1st July 2026/i);
  assertNoEmojis(dateAns, 'Date question');
});

test('Scenario 2: Question answerable from OCR text', () => {
  const context = {
    company_name: 'Hexa Corp Solutions',
    trust_score: 80,
    forensicAnalysis: {
      ocr: {
        rawText: 'HEXA CORP APPOINTMENT LETTER. Notice Period: 30 days mandatory. Reference Number: HEXA/2026/BLR-0941. Location: Cyber Park, Electronic City, Bangalore.',
      },
      semantics: {
        detectedRole: 'Software Developer Intern',
      },
      scoring: {
        structureAnalysis: {
          referenceNumber: 'HEXA/2026/BLR-0941',
        },
      },
    },
  };

  const ocrQueryAns = generateEvidenceGroundedAnswer('What is the notice period mentioned in the letter?', context);
  assert.match(ocrQueryAns, /30 days/i);
  assertNoEmojis(ocrQueryAns, 'OCR query');

  const refAns = generateEvidenceGroundedAnswer('What is the document reference number?', context);
  assert.match(refAns, /HEXA\/2026\/BLR-0941/i);
  assertNoEmojis(refAns, 'Ref number query');
});

test('Scenario 3: Question answerable from stored external search (Reddit, LinkedIn, MCA)', () => {
  const context = {
    company_name: 'TechScam Ltd',
    trust_score: 22,
    external_research: {
      targetCompany: 'TechScam Ltd',
      overallResearchRisk: 'CRITICAL',
      providers: {
        linkedin: {
          provider: 'LinkedIn',
          status: 'SUCCESS',
          riskSignal: 'CRITICAL',
          summary: 'Recruiter uses unverified gmail webmail; no corporate employee directory match.',
          findings: [],
        },
        reddit: {
          provider: 'Reddit',
          status: 'SUCCESS',
          riskSignal: 'CRITICAL',
          summary: 'Multiple threads in r/developersIndia reporting fake job offers and 5000 INR deposit scams.',
          findings: [
            {
              platform: 'REDDIT',
              title: 'Beware of TechScam Ltd asking 5000 rs caution money',
              url: 'https://reddit.com/r/developersIndia/comments/123456',
              snippet: 'They promised 40k stipend but asked 5k deposit before sending laptop. Total scam.',
              sentiment: 'CRITICAL',
            },
          ],
        },
        mca: {
          provider: 'MCA Registry',
          status: 'SUCCESS',
          riskSignal: 'LOW',
          summary: 'TechScam Private Limited is registered with CIN U72200KA2020PTC123456.',
          findings: [],
        },
      },
      allFindings: [
        {
          platform: 'REDDIT',
          title: 'Beware of TechScam Ltd asking 5000 rs caution money',
          url: 'https://reddit.com/r/developersIndia/comments/123456',
          snippet: 'They promised 40k stipend but asked 5k deposit before sending laptop. Total scam.',
          sentiment: 'CRITICAL',
        },
      ],
    },
  };

  // Reddit query
  const redditAns = generateEvidenceGroundedAnswer('Did Reddit or forums say anything about scams for this company?', context);
  assert.match(redditAns, /Reddit/i);
  assert.match(redditAns, /r\/developersIndia/i);
  assert.match(redditAns, /scam|TechScam/i);
  assertNoEmojis(redditAns, 'Reddit query');

  // LinkedIn query
  const linkedinAns = generateEvidenceGroundedAnswer('What did LinkedIn research show about the recruiter and company?', context);
  assert.match(linkedinAns, /LinkedIn/i);
  assert.match(linkedinAns, /webmail|corporate/i);
  assertNoEmojis(linkedinAns, 'LinkedIn query');

  // Consolidated internet search query
  const internetAns = generateEvidenceGroundedAnswer('What did internet searches reveal about this company?', context);
  assert.match(internetAns, /LinkedIn/i);
  assert.match(internetAns, /Reddit/i);
  assert.match(internetAns, /MCA/i);
  assertNoEmojis(internetAns, 'Internet searches query');
});

test('Scenario 4: Comparison between document claims and external reality', () => {
  const context = {
    company_name: 'Apex Global Inc',
    trust_score: 25,
    document_analysis: {
      extracted_text: 'Apex Global Inc. Direct appointment as Lead Architect without interview. Contact hr-apex@gmail.com. Please deposit 10,000 INR refundable caution fee.',
      semantics: {
        recruiterEmail: 'hr-apex@gmail.com',
        isFreeWebmail: true,
        hasFeeDemand: true,
        hasDirectSelectionNoInterview: true,
      },
    },
    external_research: {
      providers: {
        mca: {
          summary: 'Apex Global Private Limited is an active registered entity.',
        },
      },
    },
  };

  const comparisonAns = generateEvidenceGroundedAnswer('Compare what the letter claims versus what external reality shows.', context);
  assert.match(comparisonAns, /comparison between what the uploaded document claims/i);
  assert.match(comparisonAns, /hr-apex@gmail\.com|webmail/i);
  assert.match(comparisonAns, /caution|fee/i);
  assert.match(comparisonAns, /interview/i);
  assertNoEmojis(comparisonAns, 'Comparison query');
});

test('Scenario 5: Unseen user-generated questions (Does this offer look fraudulent? Explain why.)', () => {
  const context = {
    company_name: 'RapidHire India',
    trust_score: 18,
    verdict: 'HIGH RISK / SUSPICIOUS OFFER',
    document_analysis: {
      extracted_text: 'RapidHire India. Pay 3,000 INR registration fee to UPI rapid@upi.',
      semantics: {
        hasFeeDemand: true,
        recruiterEmail: 'recruiter@gmail.com',
        isFreeWebmail: true,
      },
      fee_details: [
        {
          category: 'Registration Fee',
          amount: 'INR 3,000',
          recipient: 'rapid@upi',
          exact_quote: 'Pay 3,000 INR registration fee to UPI rapid@upi.',
        },
      ],
    },
  };

  const fraudAns = generateEvidenceGroundedAnswer('Does this offer letter look fraudulent? Explain why.', context);
  assert.match(fraudAns.split('\n')[0], /critical indicators of recruitment fraud|18\/100/i);
  assert.match(fraudAns, /Mandatory Candidate Fee/i);
  assert.match(fraudAns, /Company Existence != Offer Authenticity/i);
  assertNoEmojis(fraudAns, 'Fraud explanation');
});

test('Scenario 6: Detailed multi-paragraph response requests', () => {
  const context = {
    company_name: 'CyberTech Labs',
    trust_score: 20,
    verdict: 'CRITICAL RECRUITMENT FRAUD',
    document_analysis: {
      extracted_text: 'CyberTech Labs offer letter. Candidate deposit required.',
      semantics: { hasFeeDemand: true },
    },
  };

  const detailedAns = generateEvidenceGroundedAnswer('Give me a detailed conclusion and comprehensive analysis of this letter.', context);
  const paragraphs = detailedAns.split('\n\n').filter(p => p.trim().length > 30);
  assert.ok(paragraphs.length >= 3, `Expected at least 3 detailed paragraphs, got ${paragraphs.length}`);
  assert.match(detailedAns, /Executive Verdict and Authenticity Score/i);
  assert.match(detailedAns, /Core Forensic Findings/i);
  assert.match(detailedAns, /Strategic Action Recommendation/i);
  assertNoEmojis(detailedAns, 'Detailed conclusion query');
});

test('Scenario 7: Follow-up questions with conversation context (simpler terms, why that conclusion, 3 bullets)', () => {
  const context = {
    company_name: 'Global Tech',
    trust_score: 24,
    verdict: 'HIGH RISK',
    document_analysis: {
      extracted_text: 'Global Tech. Security deposit Rs. 4,000 required before start.',
      semantics: {
        hasFeeDemand: true,
        recruiterEmail: 'hr@yahoo.com',
        isFreeWebmail: true,
      },
    },
    history: [
      { role: 'user', content: 'Why did you give this score?' },
      { role: 'assistant', content: 'The trust score is 24/100 due to upfront deposit demands and webmail communication.' },
    ],
  };

  // Simpler terms
  const simpleAns = generateEvidenceGroundedAnswer('Can you explain in simpler terms?', context);
  assert.match(simpleAns, /In simple terms/i);
  assert.match(simpleAns, /Real companies will never ask you to pay money/i);
  assertNoEmojis(simpleAns, 'Simpler terms query');

  // Why that conclusion
  const whyAns = generateEvidenceGroundedAnswer('Why did you reach that conclusion?', context);
  assert.match(whyAns, /reached this conclusion through a systematic/i);
  assertNoEmojis(whyAns, 'Reasoning chain query');

  // Summarize in 3 bullet points
  const bulletAns = generateEvidenceGroundedAnswer('Summarize this in 3 bullet points.', context);
  assert.match(bulletAns, /in exactly 3 key points/i);
  assert.match(bulletAns, /1\./);
  assert.match(bulletAns, /2\./);
  assert.match(bulletAns, /3\./);
  assertNoEmojis(bulletAns, '3 bullet points query');
});

test('Scenario 8: Questions asking for evidence supporting or contradicting assessment', () => {
  const context = {
    company_name: 'Zeta Solutions',
    trust_score: 30,
    document_analysis: {
      extracted_text: 'Zeta Solutions. Role: Data Analyst Intern. Remuneration: 15,000/month. Deposit: 2,000 refundable.',
      semantics: {
        detectedRole: 'Data Analyst Intern',
        detectedStipend: '15,000/month',
        hasFeeDemand: true,
        recruiterEmail: 'hr@gmail.com',
        isFreeWebmail: true,
      },
    },
  };

  const supportAns = generateEvidenceGroundedAnswer('What evidence supports or contradicts the assessment? Show what is confirmed vs uncertain.', context);
  assert.match(supportAns, /Confirmed \/ Evidentiary Findings/i);
  assert.match(supportAns, /Uncertain \/ Unverified Parameters/i);
  assert.match(supportAns, /Limitations/i);
  assertNoEmojis(supportAns, 'Confirmed vs uncertain query');
});

test('Scenario 9: Ambiguous question handling', () => {
  const context = {
    company_name: 'Beta Innovations',
    trust_score: 80,
    document_analysis: {
      extracted_text: 'Beta Innovations offer letter. Role: Frontend Engineer.',
      semantics: {
        detectedRole: 'Frontend Engineer',
      },
    },
  };

  const ambAns = generateEvidenceGroundedAnswer('Does the document talk about parking space and lunch facilities?', context);
  assert.match(ambAns, /does not contain an explicit clause directly addressing this/i);
  assert.match(ambAns, /Beta Innovations/i);
  assertNoEmojis(ambAns, 'Ambiguous/missing clause query');
});

test('Scenario 10: Unsupported evidence handling (honest not verified)', () => {
  const context = {
    company_name: 'InnovateX',
    trust_score: 82,
    document_analysis: {
      extracted_text: 'InnovateX employment agreement. Full time role.',
    },
  };

  const unverifiedAns = generateEvidenceGroundedAnswer('Can you confirm the health insurance coverage and dental plan from this letter?', context);
  assert.match(unverifiedAns, /does not contain an explicit clause directly addressing this/i);
  assertNoEmojis(unverifiedAns, 'Unsupported claim query');
});

test('Scenario 11: Conflicting external findings (e.g. valid MCA but scam complaints on Reddit)', () => {
  const context = {
    company_name: 'OmniCorp India Pvt Ltd',
    trust_score: 35,
    document_analysis: {
      extracted_text: 'OmniCorp India Pvt Ltd. Contact omni-hr@gmail.com. Mandatory caution deposit of INR 6,000.',
      semantics: {
        recruiterEmail: 'omni-hr@gmail.com',
        isFreeWebmail: true,
        hasFeeDemand: true,
      },
    },
    external_research: {
      providers: {
        mca: {
          status: 'SUCCESS',
          summary: 'OmniCorp India Private Limited is an active registered company in MCA21 registry (CIN: U72200MH2018PTC123456).',
        },
        reddit: {
          status: 'SUCCESS',
          riskSignal: 'CRITICAL',
          summary: 'Active threads in r/scams reporting impersonators using OmniCorp India name to demand 6000 INR deposits.',
        },
      },
    },
  };

  const conflictAns = generateEvidenceGroundedAnswer('The company is legally registered on MCA, so why is this offer flagged as risky?', context);
  assert.match(conflictAns, /Company Existence != Offer Authenticity/i);
  assert.match(conflictAns, /impersonat/i);
  assertNoEmojis(conflictAns, 'Conflicting findings query');
});

test('Scenario 12: Investigation isolation test (confirming scan A data is not used for scan B)', () => {
  const contextScanA = {
    scan_id: 'scan-alpha-111',
    company_name: 'Company Alpha',
    trust_score: 92,
    document_analysis: {
      extracted_text: 'Company Alpha genuine letter. Role: Cloud Architect. Zero fees.',
    },
  };

  const contextScanB = {
    scan_id: 'scan-beta-222',
    company_name: 'Company Beta',
    trust_score: 15,
    document_analysis: {
      extracted_text: 'Company Beta fraudulent letter. Role: Trainee. Fee demanded: 10,000 INR.',
      semantics: { hasFeeDemand: true },
      fee_details: [{ amount: '10,000 INR' }],
    },
  };

  const ansA = generateEvidenceGroundedAnswer('Does this letter demand any fee?', contextScanA);
  assert.match(ansA, /Zero candidate registration fees/i);
  assert.doesNotMatch(ansA, /10,000 INR/i);
  assert.doesNotMatch(ansA, /Company Beta/i);

  const ansB = generateEvidenceGroundedAnswer('Does this letter demand any fee?', contextScanB);
  assert.match(ansB, /explicit candidate monetary payment demand/i);
  assert.match(ansB, /10,000 INR/i);
  assert.doesNotMatch(ansB, /Company Alpha/i);
});

test('Scenario 13: Payment and Financial Fee Safety across 6 distinct cases', () => {
  // Case A: Warning against payment
  const warnContext = {
    company_name: 'TCS Infotech',
    payment_case: 'WARNING_AGAINST_PAYMENT',
    assessments: [{ id: 'financial_safety', risk_score: 3, exact_quote: 'TCS never asks for any money or deposit.' }],
  };
  const warnAns = generateEvidenceGroundedAnswer('Is there any payment risk in this offer?', warnContext);
  assert.match(warnAns, /explicit anti-fraud warning/i);
  assert.match(warnAns, /3\/100/i);
  assertNoEmojis(warnAns, 'Warning against payment');

  // Case B: Policy mention without demand
  const policyContext = {
    company_name: 'Infosys Ltd',
    payment_case: 'POLICY_MENTION_WITHOUT_DEMAND',
    assessments: [{ id: 'financial_safety', risk_score: 10, exact_quote: 'Travel expenses will be reimbursed as per policy.' }],
  };
  const policyAns = generateEvidenceGroundedAnswer('Are there any fees or deposits?', policyContext);
  assert.match(policyAns, /no candidate payment is demanded/i);
  assert.match(policyAns, /10\/100/i);
  assertNoEmojis(policyAns, 'Policy mention');

  // Case C: Refundable caution deposit
  const condContext = {
    company_name: 'Wipro Tech',
    payment_case: 'CONDITIONAL_DEMAND',
    fee_details: [{ amount: 'INR 5,000', is_refundable: true, category: 'Laptop deposit' }],
    assessments: [{ id: 'financial_safety', risk_score: 85, amount: 'INR 5,000' }],
  };
  const condAns = generateEvidenceGroundedAnswer('What is the deposit policy?', condContext);
  assert.match(condAns, /conditional or refundable security deposit/i);
  assert.match(condAns, /85\/100/i);
  assertNoEmojis(condAns, 'Conditional demand');

  // Case D: Explicit demand
  const explicitContext = {
    company_name: 'FakeCorp',
    payment_case: 'EXPLICIT_DEMAND',
    fee_details: [{ amount: 'INR 2,500', recipient: 'fake@upi' }],
    assessments: [{ id: 'financial_safety', risk_score: 96, amount: 'INR 2,500' }],
  };
  const explicitAns = generateEvidenceGroundedAnswer('Does this ask for money?', explicitContext);
  assert.match(explicitAns, /explicit candidate monetary payment demand/i);
  assert.match(explicitAns, /96\/100/i);
  assertNoEmojis(explicitAns, 'Explicit demand');

  // Case E: Ambiguous evidence
  const ambContext = {
    company_name: 'Obscure LLC',
    payment_case: 'AMBIGUOUS_EVIDENCE',
    assessments: [{ id: 'financial_safety', risk_score: 45, exact_quote: 'Payment terms pending.' }],
  };
  const ambFeeAns = generateEvidenceGroundedAnswer('Is there a fee asked here?', ambContext);
  assert.match(ambFeeAns, /ambiguous or incomplete/i);
  assert.match(ambFeeAns, /45\/100/i);
  assertNoEmojis(ambFeeAns, 'Ambiguous evidence');

  // Case F: Zero payment evidence
  const zeroContext = {
    company_name: 'Google India',
    payment_case: 'NO_PAYMENT_EVIDENCE',
    extracted_offer_parts: { stipends: [{ rawText: 'INR 75,000/month' }] },
    assessments: [{ id: 'financial_safety', risk_score: 5 }],
  };
  const zeroAns = generateEvidenceGroundedAnswer('Is any deposit requested?', zeroContext);
  assert.match(zeroAns, /zero candidate registration fees/i);
  assert.match(zeroAns, /5\/100/i);
  assertNoEmojis(zeroAns, 'Zero payment evidence');
});

test('Scenario 14: Domain guardrail & off-topic handling', () => {
  assert.equal(isDomainOffTopic('What is the recipe for chocolate cake?'), true);
  assert.equal(isDomainOffTopic('Who won the cricket world cup?'), true);
  assert.equal(isDomainOffTopic('Can you play a video game with me?'), true);

  const offTopicAns = generateEvidenceGroundedAnswer('What is the recipe for chocolate cake?', {});
  assert.equal(offTopicAns, DOMAIN_GUARDRAIL_MESSAGE);
  assertNoEmojis(offTopicAns, 'Domain guardrail response');

  assert.equal(isDomainOffTopic('Hello, can you help me?'), false);
  assert.equal(isDomainOffTopic('Is this job offer real?'), false);
  assert.equal(isDomainOffTopic('Why is the stipend so high?'), false);
});

test('formatExternalResearchForPrompt formats cleanly without raw JSON slicing', () => {
  const research = {
    targetCompany: 'Acme Corp',
    overallResearchRisk: 'LOW',
    synthesizedContextForAI: 'Corporate profile verified.',
    providers: {
      linkedin: { status: 'SUCCESS', riskSignal: 'LOW', summary: 'Active corporate profile with 500+ employees.' },
      reddit: { status: 'SUCCESS', riskSignal: 'LOW', summary: 'No scam reports found.' },
      mca: { status: 'SUCCESS', riskSignal: 'LOW', summary: 'Active CIN.' },
    },
    allFindings: [
      { platform: 'LINKEDIN', title: 'Acme Official', sentiment: 'POSITIVE', snippet: 'Leading software firm', url: 'https://linkedin.com' },
    ],
  };

  const formatted = formatExternalResearchForPrompt(research);
  assert.match(formatted, /Target Company: Acme Corp/);
  assert.match(formatted, /LinkedIn Directory/);
  assert.match(formatted, /Reddit Candidate Forums/);
  assert.match(formatted, /MCA Statutory Registry/);
  assert.doesNotMatch(formatted, /\{"targetCompany":/);
});

test('Scenario 15: Conversational intents for ML classifier, domain, recruiter, and next steps', () => {
  const context = {
    company_name: 'Stripe Global Services',
    trust_score: 28,
    verdict: 'HIGH RISK',
    mlPrediction: {
      predicted_label: 1,
      fraud_probability: 0.885,
    },
    assessments: [
      { id: 'ml_fraud_pattern', name: 'Machine Learning Fraud Model', risk_score: 89, risk_band_label: 'Critical Risk', evidence_found: 'Linear SVM detected 14 high-risk n-grams.' },
      { id: 'domain_intelligence', name: 'Domain Age & Web Infrastructure', risk_score: 82, risk_band_label: 'High Risk', evidence_found: 'Domain registered 14 days ago via privacy proxy.' },
      { id: 'recruiter_email', name: 'Recruiter Email Domain Authenticity', risk_score: 95, risk_band_label: 'Critical Risk', evidence_found: 'Recruiter uses stripe-careers@gmail.com personal webmail.' },
    ],
    document_analysis: {
      extracted_text: 'Stripe Global Services offer. Contact stripe-careers@gmail.com.',
      semantics: {
        recruiterEmail: 'stripe-careers@gmail.com',
        isFreeWebmail: true,
      },
    },
  };

  // ML query
  const mlAns = generateEvidenceGroundedAnswer('What does the machine learning classifier say about this offer?', context);
  assert.match(mlAns, /Machine Learning Fraud Classifier/i);
  assert.match(mlAns, /89\/100|88\.5%/i);
  assert.match(mlAns, /Linear Support Vector Machine|Linear SVM/i);
  assertNoEmojis(mlAns, 'ML classifier query');

  // Domain query
  const domainAns = generateEvidenceGroundedAnswer('How old is the domain and is the website legitimate?', context);
  assert.match(domainAns, /Domain & Web Infrastructure/i);
  assert.match(domainAns, /Domain Longevity/i);
  assertNoEmojis(domainAns, 'Domain query');

  // Recruiter query
  const recruiterAns = generateEvidenceGroundedAnswer('Is the recruiter email legit or suspicious?', context);
  assert.match(recruiterAns, /Recruiter Legitimacy/i);
  assert.match(recruiterAns, /stripe-careers@gmail\.com/i);
  assert.match(recruiterAns, /Personal Webmail/i);
  assertNoEmojis(recruiterAns, 'Recruiter query');

  // Next steps query
  const nextAns = generateEvidenceGroundedAnswer('What should my next steps be?', context);
  assert.match(nextAns, /Action Plan/i);
  assert.match(nextAns, /Do NOT Transfer Any Money/i);
  assert.match(nextAns, /1930/i);
  assertNoEmojis(nextAns, 'Next steps query');
});

test('Scenario 16: "is it an internship offer" directly answers in first sentence without rigid template headers', () => {
  const internshipContext = {
    company_name: 'Infosys Limited',
    trust_score: 92,
    verdict: 'LOW RISK',
    document_analysis: {
      extracted_text: 'INFOSYS LIMITED INTERNSHIP OFFER LETTER. We are pleased to offer you the position of Systems Engineer Intern for a duration of 6 months. Stipend: Rs. 25,000 per month.',
      extracted_claims: [
        { field: 'Role', value: 'Systems Engineer Intern', source_quote: 'position of Systems Engineer Intern' },
      ],
    },
  };

  const answer = generateEvidenceGroundedAnswer('is it an internship offer', internshipContext);

  // Must answer directly in the opening sentence
  assert.match(answer.split('\n')[0], /internship offer/i, 'First line should state whether it is an internship offer');
  assert.match(answer, /Systems Engineer Intern/i);
  assert.match(answer, /6 months/i);
  assert.match(answer, /25,000/i);

  // Must NOT contain the old rigid template headers
  assert.doesNotMatch(answer, /### 🔍 Investigation Findings/i, 'Should not contain old rigid findings header');
  assert.doesNotMatch(answer, /1\. Relevant Excerpts from Uploaded Document/i, 'Should not contain rigid numbered excerpt header');
  assert.doesNotMatch(answer, /2\. Contextual Forensic Analysis/i, 'Should not contain rigid forensic analysis header');
  assert.doesNotMatch(answer, /3\. Next Step/i, 'Should not contain rigid next step header');

  assertNoEmojis(answer, 'Internship conversational query');
});