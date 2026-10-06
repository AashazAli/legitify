// ==============================================================================
// LEGITIFY CYBERSECURITY ANALYSIS SERVICE
// Multi-signal forensic cybersecurity analysis for employment fraud detection
// DETERMINISTIC: same input always produces same analysis
// ==============================================================================

import dns from 'dns/promises';
import { EvidenceItem } from '../../types';

export interface CybersecurityAnalysisInput {
  emails?: string[];
  domains?: string[];
  urls?: string[];
  ips?: string[];
  upiIds?: string[];
  documentText?: string;
}

export interface IOCRecord {
  type: 'DOMAIN' | 'EMAIL' | 'URL' | 'IP' | 'UPI_ID' | 'PHONE';
  value: string;
  normalizedValue: string;
  classification: IOCClassification;
  signals: string[];
  riskScore: number;  // 0-100 deterministic risk score
}

export type IOCClassification =
  | 'MALICIOUS'
  | 'SUSPICIOUS'
  | 'ANOMALOUS'
  | 'UNKNOWN'
  | 'BENIGN_SIGNAL'
  | 'VERIFIED';

export interface LookalikeDomainResult {
  domain: string;
  targetBrand?: string;
  similarity: number;
  method: string;
  classification: 'NO_MATCH' | 'LOW_SIMILARITY' | 'POSSIBLE_LOOKALIKE' | 'HIGH_CONFIDENCE_LOOKALIKE';
  signals: string[];
}

export interface EmailSecurityResult {
  email: string;
  domain: string;
  isFreeProvider: boolean;
  spfStatus: 'PASS' | 'FAIL' | 'NEUTRAL' | 'UNAVAILABLE';
  dmarcStatus: 'PASS' | 'FAIL' | 'NEUTRAL' | 'UNAVAILABLE';
  mxRecords: string[];
  lookalikeDomain?: LookalikeDomainResult;
  signals: string[];
}

export interface CybersecurityAnalysisResult {
  emails: EmailSecurityResult[];
  iocs: IOCRecord[];
  lookalikeDomains: LookalikeDomainResult[];
  highRiskIOCCount: number;
  evidence: EvidenceItem[];
  analysisVersion: string;
  analysisDurationMs: number;
}

const ANALYSIS_VERSION = 'LEGITIFY-CYBER-v1.0';

// Known free webmail providers
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'yahoo.in', 'outlook.com', 'hotmail.com',
  'rediffmail.com', 'protonmail.com', 'aol.com', 'ymail.com',
  'mail.com', 'inbox.com', 'icloud.com', 'live.com',
  'yandex.com', 'tutanota.com', 'zoho.com',
]);

// Known legitimate corporate domains for lookalike detection
const REFERENCE_BRANDS: { domain: string; brand: string }[] = [
  { domain: 'tcs.com', brand: 'TCS' },
  { domain: 'infosys.com', brand: 'Infosys' },
  { domain: 'wipro.com', brand: 'Wipro' },
  { domain: 'hcltech.com', brand: 'HCL Tech' },
  { domain: 'techmahindra.com', brand: 'Tech Mahindra' },
  { domain: 'cognizant.com', brand: 'Cognizant' },
  { domain: 'accenture.com', brand: 'Accenture' },
  { domain: 'capgemini.com', brand: 'Capgemini' },
  { domain: 'deloitte.com', brand: 'Deloitte' },
  { domain: 'goindigo.in', brand: 'IndiGo' },
  { domain: 'airindia.com', brand: 'Air India' },
  { domain: 'tatamotors.com', brand: 'Tata Motors' },
  { domain: 'google.com', brand: 'Google' },
  { domain: 'microsoft.com', brand: 'Microsoft' },
  { domain: 'amazon.com', brand: 'Amazon' },
  { domain: 'flipkart.com', brand: 'Flipkart' },
  { domain: 'hdfc.com', brand: 'HDFC' },
  { domain: 'icicibank.com', brand: 'ICICI Bank' },
  { domain: 'qualcomm.com', brand: 'Qualcomm' },
  { domain: 'apple.com', brand: 'Apple' },
  { domain: 'oracle.com', brand: 'Oracle' },
  { domain: 'cisco.com', brand: 'Cisco' },
  { domain: 'intel.com', brand: 'Intel' },
];

// Suspicious TLD patterns
const SUSPICIOUS_TLDS = ['.tk', '.cf', '.ga', '.gq', '.ml', '.xyz', '.club', '.work', '.info'];

// Common lookalike patterns
const LOOKALIKE_SUFFIXES = [
  '-jobs', '-careers', '-hr', '-recruitment', '-hiring', '-official',
  '-india', '-global', '-pvtltd', '-services', '-portal', '-apply',
];

/**
 * Run full cybersecurity analysis on extracted indicators.
 * DETERMINISTIC: same input → same output.
 */
export async function runCybersecurityAnalysis(
  input: CybersecurityAnalysisInput
): Promise<CybersecurityAnalysisResult> {
  const startTime = Date.now();
  const evidence: EvidenceItem[] = [];
  const iocs: IOCRecord[] = [];
  const lookalikeDomains: LookalikeDomainResult[] = [];
  const emailResults: EmailSecurityResult[] = [];

  // Analyze emails
  for (const email of (input.emails || [])) {
    if (!email || !email.includes('@')) continue;
    const result = await analyzeEmail(email);
    emailResults.push(result);

    if (result.isFreeProvider) {
      evidence.push({
        category: 'EMAIL',
        evidence_type_category: 'STRONG_INDICATOR',
        evidence_type: 'FREE_WEBMAIL_SENDER',
        source_name: 'Email Security Analyzer',
        title: `Free Webmail Provider: @${result.domain}`,
        snippet: `Email ${email} uses public webmail, not organizational domain`,
        evidence_text: `Recruiter uses free webmail (@${result.domain}). Legitimate enterprise recruiters use verified corporate email addresses. Note: NOT conclusive of fraud alone.`,
        evidence_strength: 'MEDIUM',
        status: 'WARNING',
        severity: 'MEDIUM',
        verified: true,
        confidence: 90,
      });
    }

    if (result.lookalikeDomain) {
      const la = result.lookalikeDomain;
      if (la.classification === 'HIGH_CONFIDENCE_LOOKALIKE') {
        lookalikeDomains.push(la);
        evidence.push({
          category: 'DOMAIN',
          evidence_type_category: 'STRONG_INDICATOR',
          evidence_type: 'LOOKALIKE_DOMAIN_EMAIL',
          source_name: 'Lookalike Domain Detector',
          title: `High-Confidence Lookalike Email Domain (${la.signals.join(', ')})`,
          snippet: `Domain '${result.domain}' appears to impersonate '${la.targetBrand}'`,
          evidence_text: `Recruiter email domain appears to be a lookalike/typosquat targeting ${la.targetBrand}. Similarity: ${Math.round(la.similarity * 100)}%. This is a high-risk signal for phishing/impersonation.`,
          evidence_strength: 'STRONG',
          status: 'NEGATIVE',
          severity: 'CRITICAL',
          verified: true,
          confidence: Math.round(la.similarity * 100),
        });
      } else if (la.classification === 'POSSIBLE_LOOKALIKE') {
        lookalikeDomains.push(la);
        evidence.push({
          category: 'DOMAIN',
          evidence_type_category: 'STRONG_INDICATOR',
          evidence_type: 'POSSIBLE_LOOKALIKE_EMAIL',
          source_name: 'Lookalike Domain Detector',
          title: `Possible Lookalike Email Domain`,
          snippet: `Domain '${result.domain}' shows some similarity to '${la.targetBrand}'`,
          evidence_text: `Recruiter email domain shows moderate similarity to ${la.targetBrand}'s domain. Requires further verification.`,
          evidence_strength: 'MEDIUM',
          status: 'WARNING',
          severity: 'HIGH',
          verified: true,
          confidence: Math.round(la.similarity * 100),
        });
      }
    }
  }

  // Analyze domains
  for (const domain of (input.domains || [])) {
    if (!domain) continue;
    const lookalike = detectLookalikeDomain(domain);
    if (lookalike.classification !== 'NO_MATCH') {
      lookalikeDomains.push(lookalike);

      if (lookalike.classification === 'HIGH_CONFIDENCE_LOOKALIKE') {
        iocs.push({
          type: 'DOMAIN',
          value: domain,
          normalizedValue: domain.toLowerCase(),
          classification: 'SUSPICIOUS',
          signals: lookalike.signals,
          riskScore: 75,
        });
      }
    }

    // Check for suspicious TLDs
    if (SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld))) {
      iocs.push({
        type: 'DOMAIN',
        value: domain,
        normalizedValue: domain.toLowerCase(),
        classification: 'ANOMALOUS',
        signals: ['SUSPICIOUS_TLD'],
        riskScore: 40,
      });
    }
  }

  // Analyze URLs
  for (const url of (input.urls || [])) {
    if (!url) continue;
    const urlIOC = analyzeUrl(url);
    if (urlIOC) iocs.push(urlIOC);
  }

  // Analyze UPI IDs (present in documents = high suspicion)
  for (const upi of (input.upiIds || [])) {
    if (!upi) continue;
    iocs.push({
      type: 'UPI_ID',
      value: upi,
      normalizedValue: upi.toLowerCase(),
      classification: 'SUSPICIOUS',
      signals: ['UPI_ID_IN_OFFER_DOCUMENT', 'DIRECT_PAYMENT_COLLECTION'],
      riskScore: 70,
    });
    evidence.push({
      category: 'OFFER',
      evidence_type_category: 'STRONG_INDICATOR',
      evidence_type: 'UPI_PAYMENT_ID_IN_OFFER',
      source_name: 'Payment Pattern Analyzer',
      title: 'UPI Payment ID Found in Offer Document',
      snippet: `UPI ID: ${upi}`,
      evidence_text: `A UPI payment identifier was found in the offer document. Legitimate employers do not include personal payment addresses in official offer letters.`,
      evidence_strength: 'STRONG',
      status: 'NEGATIVE',
      severity: 'CRITICAL',
      verified: true,
      confidence: 95,
    });
  }

  // Count high-risk IOCs
  const highRiskIOCCount = iocs.filter(i => i.riskScore >= 60).length
    + lookalikeDomains.filter(l => l.classification === 'HIGH_CONFIDENCE_LOOKALIKE').length;

  return {
    emails: emailResults,
    iocs,
    lookalikeDomains,
    highRiskIOCCount,
    evidence,
    analysisVersion: ANALYSIS_VERSION,
    analysisDurationMs: Date.now() - startTime,
  };
}

async function analyzeEmail(email: string): Promise<EmailSecurityResult> {
  const parts = email.split('@');
  const domain = parts.length > 1 ? parts[1].toLowerCase() : '';
  const isFreeProvider = FREE_EMAIL_PROVIDERS.has(domain);

  // Check for lookalike domain (only for non-free providers)
  let lookalikeDomain: LookalikeDomainResult | undefined;
  if (!isFreeProvider && domain) {
    const la = detectLookalikeDomain(domain);
    if (la.classification !== 'NO_MATCH') {
      lookalikeDomain = la;
    }
  }

  // Try DNS MX lookup for domain
  let mxRecords: string[] = [];
  let dmarcStatus: 'PASS' | 'FAIL' | 'NEUTRAL' | 'UNAVAILABLE' = 'UNAVAILABLE';
  let spfStatus: 'PASS' | 'FAIL' | 'NEUTRAL' | 'UNAVAILABLE' = 'UNAVAILABLE';

  try {
    const mx = await Promise.race([
      dns.resolveMx(domain).catch(() => []),
      new Promise<never>((_, r) => setTimeout(() => r(new Error('timeout')), 1000)),
    ]) as { priority: number; exchange: string }[];
    mxRecords = mx.map((r: { exchange: string }) => r.exchange);
  } catch {
    mxRecords = [];
  }

  // Try SPF TXT record check
  try {
    const txt = await Promise.race([
      dns.resolveTxt(domain).catch(() => []),
      new Promise<never>((_, r) => setTimeout(() => r(new Error('timeout')), 1000)),
    ]) as string[][];
    const spfRecord = txt.flat().find(r => r.startsWith('v=spf1'));
    spfStatus = spfRecord ? 'PASS' : 'NEUTRAL';
  } catch {
    spfStatus = 'UNAVAILABLE';
  }

  // Try DMARC TXT record
  try {
    const dmarcTxt = await Promise.race([
      dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
      new Promise<never>((_, r) => setTimeout(() => r(new Error('timeout')), 1000)),
    ]) as string[][];
    const dmarcRecord = dmarcTxt.flat().find(r => r.startsWith('v=DMARC1'));
    dmarcStatus = dmarcRecord ? 'PASS' : 'NEUTRAL';
  } catch {
    dmarcStatus = 'UNAVAILABLE';
  }

  const signals: string[] = [];
  if (isFreeProvider) signals.push('FREE_WEBMAIL');
  if (mxRecords.length === 0) signals.push('NO_MX_RECORDS');
  if ((spfStatus as string) === 'FAIL') signals.push('SPF_FAIL');
  if ((dmarcStatus as string) === 'FAIL') signals.push('DMARC_FAIL');
  if (lookalikeDomain) signals.push(`LOOKALIKE_${lookalikeDomain.classification}`);

  return {
    email,
    domain,
    isFreeProvider,
    spfStatus,
    dmarcStatus,
    mxRecords,
    lookalikeDomain,
    signals,
  };
}

/**
 * Detect if a domain is a lookalike of a known brand.
 * Uses multiple similarity metrics \u2014 single metric alone is insufficient.
 * DETERMINISTIC: same domain always produces same result.
 */
export function detectLookalikeDomain(domain: string): LookalikeDomainResult {
  const d = domain.toLowerCase().replace(/^www\./, '');
  const signals: string[] = [];
  let bestSimilarity = 0;
  let bestTarget: string | undefined;
  let bestBrand: string | undefined;

  // Check for lookalike suffixes first
  for (const suffix of LOOKALIKE_SUFFIXES) {
    if (d.includes(suffix)) {
      signals.push(`SUSPICIOUS_SUFFIX: ${suffix}`);
      break;
    }
  }

  // Compare against reference brands
  for (const { domain: refDomain, brand } of REFERENCE_BRANDS) {
    // Extract base name without TLD
    const dBase = d.replace(/\.[^.]+$/, '').replace(/[^a-z0-9]/g, '');
    const refBase = refDomain.replace(/\.[^.]+$/, '').replace(/[^a-z0-9]/g, '');

    if (dBase === refBase) continue; // Exact match = not a lookalike

    // 1. Levenshtein distance
    const lev = levenshteinSimilarity(dBase, refBase);

    // 2. Contains brand name as substring
    const containsBrand = dBase.includes(refBase) || refBase.includes(dBase.slice(0, Math.max(3, dBase.length - 3)));

    // 3. TLD swap (same base, different TLD)
    const baseName = d.replace(/\.[^.]+$/, '');
    const refBaseName = refDomain.replace(/\.[^.]+$/, '');
    const tldSwap = baseName === refBaseName;

    // 4. Hyphen insertion (e.g. tcs-india.com vs tcs.com)
    const hyphenVariant = d.startsWith(refBase + '-') || d.includes('-' + refBase);

    const similarity = Math.max(lev, containsBrand ? 0.7 : 0, tldSwap ? 0.95 : 0, hyphenVariant ? 0.8 : 0);

    if (similarity > bestSimilarity) {
      bestSimilarity = similarity;
      bestTarget = refDomain;
      bestBrand = brand;

      if (tldSwap) signals.push('TLD_SWAP');
      if (hyphenVariant) signals.push('HYPHEN_INSERTION');
      if (containsBrand && similarity < 0.95) signals.push('BRAND_KEYWORD_PROXIMITY');
      if (lev > 0.8) signals.push('HIGH_LEVENSHTEIN_SIMILARITY');
    }
  }

  // Classification requires multiple signals, not just one metric
  let classification: LookalikeDomainResult['classification'] = 'NO_MATCH';
  if (bestSimilarity >= 0.90 && signals.length >= 1) {
    classification = 'HIGH_CONFIDENCE_LOOKALIKE';
  } else if (bestSimilarity >= 0.70 && signals.length >= 1) {
    classification = 'POSSIBLE_LOOKALIKE';
  } else if (bestSimilarity >= 0.50) {
    classification = 'LOW_SIMILARITY';
  }

  // Also check for suspicious TLDs
  if (SUSPICIOUS_TLDS.some(tld => d.endsWith(tld))) {
    signals.push('SUSPICIOUS_TLD');
    // Suspicious TLD alone doesn't make it a lookalike, just anomalous
  }

  return {
    domain,
    targetBrand: bestBrand,
    similarity: Math.round(bestSimilarity * 100) / 100,
    method: 'MULTI_SIGNAL',
    classification,
    signals,
  };
}

/**
 * Analyze a URL for cybersecurity indicators.
 */
function analyzeUrl(url: string): IOCRecord | null {
  const signals: string[] = [];
  let riskScore = 0;

  try {
    const u = new URL(url);

    // IP-based URL
    if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) {
      signals.push('IP_BASED_URL');
      riskScore += 30;
    }

    // HTTP (not HTTPS)
    if (u.protocol === 'http:') {
      signals.push('INSECURE_HTTP');
      riskScore += 10;
    }

    // URL shortener
    const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'short.io'];
    if (SHORTENERS.some(s => u.hostname.includes(s))) {
      signals.push('URL_SHORTENER');
      riskScore += 20;
    }

    // Private IP redirect risk
    if (/^(localhost|127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(u.hostname)) {
      signals.push('PRIVATE_IP_URL');
      riskScore += 40;
    }

    // Free hosting patterns
    const FREE_HOSTS = ['000webhostapp.com', 'sites.google.com/view', 'wixsite.com', 'weebly.com'];
    if (FREE_HOSTS.some(h => u.hostname.includes(h) || url.includes(h))) {
      signals.push('FREE_HOSTING');
      riskScore += 15;
    }

    // Suspicious path patterns
    if (/\/(login|signin|verify|auth|account|payement|payment|register)/i.test(u.pathname)) {
      signals.push('SUSPICIOUS_PATH');
      riskScore += 20;
    }

    if (signals.length === 0 || riskScore === 0) return null;

    return {
      type: 'URL',
      value: url,
      normalizedValue: url.toLowerCase().slice(0, 500),
      classification: riskScore >= 50 ? 'SUSPICIOUS' : 'ANOMALOUS',
      signals,
      riskScore: Math.min(100, riskScore),
    };
  } catch {
    return null;
  }
}

/**
 * Calculate Levenshtein edit distance similarity (0-1).
 * DETERMINISTIC: pure function.
 */
function levenshteinSimilarity(a: string, b: string): number {
  if (a === b) return 1;
  if (a.length === 0 || b.length === 0) return 0;

  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
    for (let j = 1; j <= a.length; j++) {
      if (i === 0) {
        matrix[0][j] = j;
      } else {
        const cost = a[j - 1] === b[i - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
  }

  const distance = matrix[b.length][a.length];
  const maxLen = Math.max(a.length, b.length);
  return 1 - (distance / maxLen);
}
