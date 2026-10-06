import { describe, it } from 'node:test';
import assert from 'node:assert';
import { runScanPipeline } from '../services/scanPipeline';

describe('Live Scan Pipeline Integration', () => {
  it('executes end-to-end scan on a company and returns a valid 22-section report', async () => {
    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'company',
      entityValue: 'TechCorp Solutions Ltd',
    });

    assert.ok(report.scan_id, 'Report must contain a valid scan_id');
    assert.ok(report.trust_score >= 0 && report.trust_score <= 100, 'Trust score must be 0-100');
    assert.ok(report.confidence >= 0 && report.confidence <= 100, 'Confidence must be 0-100');
    assert.ok(report.verdict, 'Verdict must be present');
    assert.ok(report.executive_summary, 'Executive summary must be present');
    assert.ok(report.recommendation, 'Recommendation must be present');
    assert.strictEqual(report.entity_name, 'TechCorp Solutions Ltd');
  });

  it('detects upfront fee demands in job offer and escalates risk', async () => {
    const offerText = `
      Dear Candidate,
      Congratulations on your selection for the Web Developer Internship.
      Please pay a mandatory registration fee of Rs. 4,500 via UPI to hr.onboarding@paytm for your laptop security deposit before joining.
    `;

    const report = await runScanPipeline({
      userId: '00000000-0000-0000-0000-000000000000',
      entityType: 'job_offer',
      entityValue: 'Web Developer Internship Offer',
      contextText: offerText,
    });

    assert.ok(report.trust_score <= 45, `Expected high/critical risk score <= 45 for fee demand, got ${report.trust_score}`);
    assert.ok(
      report.risk_level === 'CRITICAL' || report.risk_level === 'HIGH',
      `Expected CRITICAL or HIGH risk level, got ${report.risk_level}`
    );
    assert.ok(
      report.critical_signals.some(s => s.toLowerCase().includes('fee') || s.toLowerCase().includes('payment')),
      'Must flag upfront fee critical signal'
    );
  });
});
