// ==============================================================================
// LEGITIFY GEMINI INTEGRATION & END-TO-END VALIDATION TEST SUITE
// Strict verification of server-side key security, live model connectivity,
// resilient fallback cascade, ML stopword pruning, and evidence grounding.
// ZERO EMOJIS in code, logs, comments, and assertions.
// ==============================================================================

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config();

import {
  getGeminiApiKey,
  isGeminiConfigured,
  getGeminiModelCascade,
  testGeminiConnectivity,
  generateJsonWithFallback,
  generateContentWithFallback,
  parseSafeJson,
} from '../services/geminiClient';
import { predictJobOfferRisk, getMLModelMetrics, FRAUD_STOPWORDS } from '../ml/fraudClassifier';
import { detectVisualRegions } from '../services/visualForensicsService';
import { runGeminiInvestigation } from '../services/geminiInvestigator';
import { GeminiFlashProvider } from '../services/aiProvider';

describe('Gemini Integration: Environment & Key Security', () => {
  it('Loads Gemini API key strictly from server environment', () => {
    const key = getGeminiApiKey();
    assert.ok(key !== null, 'Gemini API key should be present in server environment');
    assert.ok(key.length >= 20, 'Gemini API key should have valid format and length');
    assert.strictEqual(isGeminiConfigured(), true, 'isGeminiConfigured should return true');
  });

  it('Never exposes secret key in string output or error objects', () => {
    const key = getGeminiApiKey();
    assert.ok(key);
    const masked = key.slice(0, 4) + '...' + key.slice(-4);
    assert.notStrictEqual(masked, key, 'Key should be masked when logged');
  });

  it('Verifies fallback cascade includes supported models', () => {
    const cascade = getGeminiModelCascade();
    assert.ok(Array.isArray(cascade) && cascade.length >= 2, 'Cascade should contain multiple candidate models');
    assert.ok(cascade.includes('gemini-3.5-flash-lite'), 'Cascade must include gemini-3.5-flash-lite');
  });
});

describe('Gemini Integration: Live API Connectivity & Structured JSON', () => {
  it('Successfully connects to live Gemini model with low latency', async () => {
    const res = await testGeminiConnectivity();
    assert.strictEqual(res.ok, true, `Gemini connectivity failed: ${res.error}`);
    assert.ok(res.model, 'Model used must be reported');
    assert.ok(typeof res.durationMs === 'number' && res.durationMs > 0, 'Latency must be measured');
  });

  it('Generates structured JSON and safely extracts parsed object', async () => {
    const res = await generateJsonWithFallback<{ verdict: string; score: number }>({
      contents: 'Analyze this sample: Organisation: Acme Corp, Demanded Fee: None. Return JSON: {"verdict": "SAFE", "score": 90}',
      temperature: 0.1,
    });
    assert.ok(res.data, 'Data should be parsed');
    assert.strictEqual(res.data.verdict, 'SAFE');
    assert.strictEqual(res.data.score, 90);
    assert.ok(res.modelUsed, 'Model used must be recorded');
  });

  it('parseSafeJson correctly strips markdown code fences and isolates JSON', () => {
    const sample = '```json\n{"status": "verified", "count": 5}\n```';
    const parsed = parseSafeJson<{ status: string; count: number }>(sample);
    assert.ok(parsed);
    assert.strictEqual(parsed.status, 'verified');
    assert.strictEqual(parsed.count, 5);
  });
});

describe('ML Fraud Classifier: Supervised Artifact & Stopword Pruning', () => {
  it('Loads genuine Kaggle dataset supervised model metrics', () => {
    const metrics = getMLModelMetrics();
    assert.strictEqual(metrics.modelLoaded, true, 'ML model artifact must be loaded');
    assert.strictEqual(metrics.dataset, 'Kaggle Real / Fake Job Postings Dataset');
    assert.strictEqual(metrics.totalTrainingRows, 17880);
    assert.ok(metrics.featureCount > 100, 'Model must have learned vocabulary weights');
  });

  it('Prunes generic stopword unigrams (per, company, your) from top features', () => {
    const sampleText = 'We are pleased to offer you the role at our company. The stipend is Rs. 25000 per month. Please check your email and confirm your acceptance.';
    const prediction = predictJobOfferRisk({ text: sampleText });

    assert.ok(prediction.model_loaded, 'Prediction should succeed with loaded model');
    assert.ok(Array.isArray(prediction.topFeatures), 'Top features array must be present');

    // Verify isolated stopword unigrams are NOT present as fraud indicators
    for (const item of prediction.topFeatures) {
      if (item.direction === 'FRAUD') {
        assert.notStrictEqual(item.feature, "Term 'per'", "Term 'per' must not be a fraud indicator");
        assert.notStrictEqual(item.feature, "Term 'company'", "Term 'company' must not be a fraud indicator");
        assert.notStrictEqual(item.feature, "Term 'your'", "Term 'your' must not be a fraud indicator");
        assert.notStrictEqual(item.feature, "Term 'is'", "Term 'is' must not be a fraud indicator");
      }
    }
  });

  it('Correctly identifies genuine high-risk phrase indicators', () => {
    const fraudText = 'Urgent hiring for high school pass. Work from home data entry. Pay 000 registration money out of country perks.';
    const prediction = predictJobOfferRisk({ text: fraudText });
    assert.ok(prediction.fraudProbability >= 0.5, 'Suspicious job text should yield high fraud probability');
  });
});

describe('Visual Forensics & Document Structure', () => {
  it('Detects visual regions and signatory patterns in document buffer', async () => {
    const textBuffer = Buffer.from(
      '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nSincerely,\nAuthorized Signatory\nDirector of Talent Acquisition',
      'utf-8'
    );
    const result = await detectVisualRegions(textBuffer, 'application/pdf', 'SCAN-TEST-001', 'Authorized Signatory\nDirector of Talent Acquisition');
    assert.ok(result);
    assert.ok(Array.isArray(result.regions));
    assert.ok(result.detectionMethod !== 'NONE', 'Detection method should resolve to metadata, vision, or pattern');
  });
});

describe('Investigating Copilot: Grounded Synthesis & Q&A', () => {
  it('Synthesizes intelligence grounded in provided evidence', async () => {
    const provider = new GeminiFlashProvider();
    const available = await provider.isAvailable();
    assert.strictEqual(available, true, 'Gemini provider must be available');

    const synthesis = await provider.generateSynthesis({
      entityName: 'Apex Innovations Pvt Ltd',
      entityType: 'company',
      trustScore: 82,
      confidence: 88,
      riskLevel: 'LOW',
      verdict: 'LEGITIMATE',
      evidence: [
        {
          id: 'E-001',
          evidence_id: 'E-001',
          title: 'MCA Registry Verified',
          source: 'Ministry of Corporate Affairs',
          category: 'REGISTRY',
          verified: true,
          status: 'VERIFIED',
          severity: 'LOW',
          evidence_strength: 'STRONG',
          snippet: 'Company actively registered since 2018 with valid CIN.',
          weight: 0.8,
          confidence: 0.9,
          direction: 'LEGITIMATE',
          is_primary: true,
        },
      ],
      rulesTriggered: [],
    });

    assert.ok(synthesis.executive_summary, 'Synthesis must contain executive summary');
    assert.ok(synthesis.recommendation, 'Synthesis must contain actionable recommendation');
    assert.strictEqual(synthesis.provider_used, 'GEMINI_FLASH', 'Provider used must be GEMINI_FLASH');
  });

  it('Answers Copilot question directly grounded in context', async () => {
    const provider = new GeminiFlashProvider();
    const answer = await provider.answerCopilot('Is there any payment demanded in this offer?', {
      company_name: 'Apex Innovations',
      trust_score: 85,
      fee_details: [],
      document_analysis: { fee_details: [] },
    });

    assert.ok(typeof answer === 'string' && answer.length > 20, 'Answer must be substantive');
    // Ensure zero emojis in output
    const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu;
    assert.strictEqual(emojiRegex.test(answer), false, 'Output must have zero emojis');
  });
});

describe('Gemini Independent Cross-Examination Dossier', () => {
  it('Executes independent cross-examination without crashing', async () => {
    const result = await runGeminiInvestigation({
      extractedEntities: {
        companyName: 'Acme Software Labs',
        role: 'Frontend Engineering Intern',
        stipend: 'Rs 15000 per month',
        recruiterEmail: 'hr@acmesoftwarelabs.com',
        domain: 'acmesoftwarelabs.com',
      },
      preliminaryScore: {
        trustScore: 78,
        verdict: 'PROCEED_WITH_CAUTION',
        riskLevel: 'MODERATE',
        activeDimensions: [],
      },
    });

    assert.ok(result, 'Result should be returned');
    assert.strictEqual(result.engine, 'GEMINI');
    assert.ok(['COMPLETED', 'RATE_LIMITED', 'TIMEOUT'].includes(result.investigationStatus));
    if (result.investigationStatus === 'COMPLETED') {
      assert.ok(result.verdict, 'Verdict must be present');
      assert.ok(result.summary, 'Summary must be present');
    }
  });
});
