import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  normalizeCompanyName,
  normalizeDomain,
  normalizeEmail,
  isFreeEmailProvider,
  calculateLevenshteinDistance,
} from '../utils/normalizer';

describe('Normalizer Utilities', () => {
  it('normalizes company names by removing corporate suffixes', () => {
    assert.strictEqual(normalizeCompanyName('TechCorp Solutions Private Limited'), 'techcorp');
    assert.strictEqual(normalizeCompanyName('Infosys Technologies Pvt Ltd'), 'infosys');
    assert.strictEqual(normalizeCompanyName('Amazon India LLC'), 'amazon india');
  });

  it('normalizes domain names by stripping protocols, www, and paths', () => {
    assert.strictEqual(normalizeDomain('https://www.google.com/careers/'), 'google.com');
    assert.strictEqual(normalizeDomain('http://amazon-jobs.net?ref=123'), 'amazon-jobs.net');
  });

  it('correctly identifies free email providers', () => {
    assert.strictEqual(isFreeEmailProvider('recruiter@gmail.com'), true);
    assert.strictEqual(isFreeEmailProvider('hr@yahoo.co.in'), true);
    assert.strictEqual(isFreeEmailProvider('careers@amazon.com'), false);
  });

  it('calculates string edit distance for lookalike detection', () => {
    assert.strictEqual(calculateLevenshteinDistance('amazon', 'amaz0n'), 1);
    assert.strictEqual(calculateLevenshteinDistance('google', 'g00gle'), 2);
  });
});
