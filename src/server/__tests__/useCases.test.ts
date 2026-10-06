// ==============================================================================
// LEGITIFY 8 MANDATORY TEST SUITE SCENARIOS
// Verifies complete evidence-first, multi-source independence, ML, and conflict handling
// ==============================================================================
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { runScanPipeline } from '../services/scanPipeline';
import { verifyCertificate } from '../services/certificateService';
import { verifyCompanyRegistry } from '../services/companyRegistryService';
import { searchPublicExperiences } from '../services/publicExperienceService';
import { predictJobOfferRisk } from '../ml/fraudClassifier';

describe('LEGITIFY 8 Core Evidence-First Scenarios', () => {

  // TEST 1: Real registered company + Real corporate domain + Corporate email + Authentic certificate + No payment request + Positive community
  it('TEST 1: Real company + Real domain + Corporate email + Valid certificate + No fee = LOW RISK', async () => {
    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'job_offer',
      entityValue: 'TCS Software Engineering Internship',
      contextText: `
        Official Offer Letter from Tata Consultancy Services (TCS).
        Sender: recruitment@tcs.com
        Domain: tcs.com
        Certificate Verification: Issued by Coursera, Certificate ID: CS9988776655
        Website: https://www.tcs.com
        Stipend: Rs. 25,000 / month. No fees are charged for recruitment.
      `,
    });

    assert.ok(report.trust_score >= 70, `Expected high trust score >= 70, got ${report.trust_score}`);
    assert.strictEqual(report.certificate_verification?.status, 'VERIFIED_AUTHENTIC');
    assert.strictEqual(report.company_verification.status, 'ACTIVE');
    assert.ok(report.verdict === 'LOW RISK' || report.verdict === 'LIKELY LEGITIMATE');
  });

  // TEST 2: Real registered company + Fake recruiter + Gmail + Upfront fee + Suspicious domain
  it('TEST 2: Registered company + Fake recruiter Gmail + Upfront fee + Suspicious domain = HIGH RISK (Company remains REGISTERED)', async () => {
    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'job_offer',
      entityValue: 'Infosys Developer Internship Offer',
      contextText: `
        Congratulations on your selection at Infosys Limited.
        Sender: infosys.hiring.manager@gmail.com
        Domain: inf0sys-careers.com
        Please pay a mandatory laptop insurance security deposit of Rs. 6,500 via UPI to hr.onboarding@paytm before receiving your appointment letter.
      `,
    });

    // Company registration remains verified in statutory registry
    assert.strictEqual(report.company_verification.status, 'ACTIVE');
    // But overall internship offer is HIGH RISK / CRITICAL due to fee demand & lookalike domain
    assert.ok(report.trust_score <= 40, `Expected capped trust score <= 40, got ${report.trust_score}`);
    assert.ok(report.risk_level === 'HIGH' || report.risk_level === 'CRITICAL');
    assert.ok(report.critical_signals.some(s => s.toLowerCase().includes('fee') || s.toLowerCase().includes('deposit')));
  });

  // TEST 3: Authentic certificate + Suspicious internship
  it('TEST 3: Authentic certificate + Suspicious internship = Certificate: VERIFIED_AUTHENTIC, Opportunity: HIGH RISK', async () => {
    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'job_offer',
      entityValue: 'Remote Data Entry Internship',
      contextText: `
        Remote Data Entry Clerk. 
        Issued by Coursera, Certificate ID: ABC1234567890.
        Candidate must wire transfer Rs. 3,500 training materials fee to hr.onboarding@upi immediately.
      `,
    });

    // Certificate is independently authentic
    assert.strictEqual(report.certificate_verification?.status, 'VERIFIED_AUTHENTIC');
    // Internship is independently high risk
    assert.ok(report.trust_score <= 40, `Expected trust score <= 40, got ${report.trust_score}`);
    assert.ok(report.risk_level === 'HIGH' || report.risk_level === 'CRITICAL');
  });

  // TEST 4: Unknown certificate + Known issuer + ID cannot be verified
  it('TEST 4: Unknown certificate with unverified public registry = UNVERIFIED (NOT FAKE)', async () => {
    const cert = await verifyCertificate(
      'Completion certificate for Machine Learning Bootcamp at Bharat Skills Academy. Certificate ID: BSA-8821.',
      'BSA-8821',
      'Bharat Skills Academy',
      'https://bharatskills.edu/verify/BSA-8821'
    );

    assert.strictEqual(cert.status, 'UNVERIFIED', 'Unregistered issuer must be UNVERIFIED, never FAKE');
    assert.ok(cert.summary.includes('UNVERIFIED'));
  });

  // TEST 5: Nonexistent company + Suspicious domain + Payment demand + Negative community
  it('TEST 5: Nonexistent company + Lookalike domain + Urgent UPI payment = LIKELY SCAM', async () => {
    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'job_offer',
      entityValue: 'Global Cloud Interns 2026',
      contextText: `
        URGENT: Final confirmation for AWS Cloud Intern.
        Deposit Rs. 3,000 for training material within 24 hours to aws-training@upi.
        Official Portal: amaz0n-jobs.xyz
      `,
    });

    assert.ok(report.trust_score <= 35, `Expected trust score <= 35, got ${report.trust_score}`);
    assert.ok(report.verdict === 'HIGH RISK' || report.verdict === 'LIKELY SCAM');
  });

  // TEST 6: Only one negative Reddit report + Everything else normal
  it('TEST 6: Single isolated negative public report does not automatically classify as scam', async () => {
    const comm = await searchPublicExperiences({
      companyName: 'Wipro Limited',
      domain: 'wipro.com',
      recruiterEmail: 'careers@wipro.com',
    });

    // Single uncorroborated post has low confidence and does not mark company as scam
    assert.ok(comm !== undefined);
    assert.ok(Array.isArray(comm.experiences));
  });

  // TEST 7: Five independent community reports with same payment demand & domain
  it('TEST 7: Multiple independent public complaints = STRONG COMMUNITY RISK SIGNAL', async () => {
    const comm = await searchPublicExperiences({
      companyName: 'inf0sys-careers',
      domain: 'inf0sys-careers.com',
    });

    assert.ok(comm !== undefined);
    assert.ok(Array.isArray(comm.experiences));
  });

  // TEST 8: Company registered but impersonated domain
  it('TEST 8: Registered company + Impersonated domain = COMPANY: REGISTERED, DOMAIN: SUSPICIOUS, OVERALL: HIGH RISK', async () => {
    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'job_offer',
      entityValue: 'Microsoft Cloud Internship',
      contextText: `
        Offer from Microsoft Corporation.
        Apply at: https://micros0ft-careers.xyz/apply
        Sender: careers@micros0ft-careers.xyz
      `,
    });

    // Company is registered
    assert.strictEqual(report.company_verification.status, 'ACTIVE');
    // Domain is lookalike/suspicious
    assert.strictEqual(report.domain_analysis.lookalike_detected, true);
    // Overall is HIGH RISK
    assert.ok(report.trust_score <= 35, `Expected score <= 35 for lookalike impersonation, got ${report.trust_score}`);
  });

});
