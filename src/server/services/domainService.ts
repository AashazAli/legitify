// ==============================================================================
// DOMAIN INTELLIGENCE SERVICE
// ==============================================================================
import dns from 'dns/promises';
import tls from 'tls';
import { normalizeDomain, calculateLevenshteinDistance } from '../utils/normalizer';
import { EvidenceItem } from '../../types';

const MAJOR_TECH_DOMAINS = [
  "amazon.com", "google.com", "microsoft.com", "apple.com", "meta.com",
  "netflix.com", "adobe.com", "salesforce.com", "oracle.com", "ibm.com",
  "tcs.com", "infosys.com", "wipro.com", "hcltech.com", "techmahindra.com",
  "cognizant.com", "accenture.com", "deloitte.com", "capgemini.com",
  "tatamotors.com", "goindigo.in", "airindia.com", "spicejet.com", "reliance.com",
  "qualcomm.com", "intel.com", "cisco.com"
];

export type DomainData = DomainAnalysisData;
export interface DomainAnalysisData {
  domain: string;
  has_dns: boolean;
  mx_records: string[];
  a_records: string[];
  txt_records: string[];
  ssl_valid: boolean;
  ssl_issuer?: string;
  ssl_days_remaining?: number;
  registrar?: string;
  registration_date?: string;
  expiration_date?: string;
  age_days?: number;
  virustotal_positives?: number;
  safe_browsing_threats?: string[];
  lookalike_detected: boolean;
  lookalike_target?: string;
  reputation_score?: number;
  threat_status?: string;
}

export async function analyzeDomain(domainInput: string): Promise<{
  data: DomainAnalysisData;
  evidence: EvidenceItem[];
  score_modifier: number;
}> {
  const domain = normalizeDomain(domainInput);
  const evidence: EvidenceItem[] = [];
  let score_modifier = 0;

  const data: DomainAnalysisData = {
    domain,
    has_dns: false,
    mx_records: [],
    a_records: [],
    txt_records: [],
    ssl_valid: false,
    lookalike_detected: false,
  };

  if (!domain || !domain.includes('.')) {
    return { data, evidence, score_modifier };
  }

  function withTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
    return Promise.race([
      p,
      new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms))
    ]);
  }

  // 1. Parallel DNS Resolution (A, MX, TXT) with 1200ms timeout
  try {
    const [aRecords, mxRecords, txtRecords] = await Promise.all([
      withTimeout(dns.resolve4(domain).catch(() => []), 1200, []),
      withTimeout(dns.resolveMx(domain).catch(() => []), 1200, []),
      withTimeout(dns.resolveTxt(domain).catch(() => []), 1200, []),
    ]);

    data.a_records = aRecords;
    data.mx_records = mxRecords.map(m => m.exchange);
    data.txt_records = txtRecords.flat();
    data.has_dns = aRecords.length > 0 || mxRecords.length > 0;

    if (data.has_dns) {
      evidence.push({
        category: "DOMAIN",
        evidence_type: "DNS_RECORDS",
        source_name: "Authoritative DNS Resolver",
        title: "Active DNS Records Confirmed",
        snippet: `A Records: ${aRecords.join(', ') || 'None'} · MX Records: ${data.mx_records.join(', ') || 'None'}`,
        evidence_text: `Domain resolves with ${aRecords.length} A records and ${mxRecords.length} MX mail servers.`,
        evidence_strength: "STRONG",
        status: "VERIFIED",
        severity: "INFO",
        verified: true,
        confidence: 100.0,
      });
      score_modifier += 15;
    } else {
      evidence.push({
        category: "DOMAIN",
        evidence_type: "DNS_RESOLUTION_FAILURE",
        source_name: "Authoritative DNS Resolver",
        title: "DNS Resolution Failed",
        snippet: `No A or MX records found for domain ${domain}.`,
        evidence_text: "Domain does not have active DNS records, indicating a non-functional or expired host.",
        evidence_strength: "VERY_STRONG",
        status: "NEGATIVE",
        severity: "HIGH",
        verified: true,
        confidence: 95.0,
      });
      score_modifier -= 30;
    }
  } catch (err) {
    // Graceful DNS error
  }

  // 2. SSL/TLS Inspection
  try {
    const sslPromise = new Promise<{ valid: boolean; issuer?: string; daysRemaining?: number }>((resolve) => {
      const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: 3500 }, () => {
        const cert = socket.getPeerCertificate();
        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.round((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
          socket.end();
          const rawO = cert.issuer?.O;
          const issuerOrg = Array.isArray(rawO) ? rawO.join(', ') : rawO;
          const rawCN = cert.issuer?.CN;
          const issuerCN = Array.isArray(rawCN) ? rawCN.join(', ') : rawCN;
          resolve({
            valid: socket.authorized !== false,
            issuer: issuerOrg || issuerCN || 'Unknown CA',
            daysRemaining,
          });
        } else {
          socket.end();
          resolve({ valid: false });
        }
      });
      socket.on('error', () => resolve({ valid: false }));
      socket.on('timeout', () => { socket.destroy(); resolve({ valid: false }); });
    });

    const ssl = await sslPromise;
    data.ssl_valid = ssl.valid;
    data.ssl_issuer = ssl.issuer;
    data.ssl_days_remaining = ssl.daysRemaining;

    if (ssl.valid) {
      evidence.push({
        category: "DOMAIN",
        evidence_type: "TLS_CERTIFICATE_VALID",
        source_name: "TLS / X.509 Certificate Chain",
        title: "Valid TLS Certificate (Infrastructure Fact)",
        snippet: `Issued by ${ssl.issuer || 'Trusted CA'} · ${ssl.daysRemaining || 0} days remaining`,
        evidence_text: `Domain presents a valid TLS certificate issued by ${ssl.issuer}. NOTE: Valid TLS confirms encrypted transport only. It is an infrastructure fact, NOT proof of organizational authenticity or that the domain owner is who they claim to be.`,
        evidence_strength: "MEDIUM",
        status: "VERIFIED",
        severity: "INFO",
        verified: true,
        confidence: 90.0,
      });
      score_modifier += 5;
    }
  } catch {
    // SSL check failed
  }

  // 3. RDAP WHOIS Lookup (Free open API)
  try {
    const rdapRes = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { 'Accept': 'application/rdap+json' },
      signal: AbortSignal.timeout(4000),
    });
    if (rdapRes.ok) {
      const rdapData = await rdapRes.json();
      const events: any[] = rdapData.events || [];
      const regEvent = events.find((e: any) => e.eventAction === 'registration');
      const expEvent = events.find((e: any) => e.eventAction === 'expiration');

      if (regEvent?.eventDate) {
        data.registration_date = regEvent.eventDate;
        const regDate = new Date(regEvent.eventDate);
        const ageDays = Math.round((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
        data.age_days = ageDays;

        if (ageDays < 30) {
          evidence.push({
            category: "DOMAIN",
            evidence_type: "NEWLY_REGISTERED_DOMAIN",
            source_name: "ICANN RDAP Service",
            title: "Newly Registered Domain (< 30 days old)",
            snippet: `Registered on ${regDate.toISOString().split('T')[0]} (${ageDays} days old)`,
            evidence_text: `Domain was created only ${ageDays} days ago. Newly registered domains are disproportionately used in phishing and impersonation.`,
            evidence_strength: "STRONG",
            status: "WARNING",
            severity: "HIGH",
            verified: true,
            confidence: 95.0,
          });
          score_modifier -= 25;
        } else {
          evidence.push({
            category: "DOMAIN",
            evidence_type: "ESTABLISHED_DOMAIN",
            source_name: "ICANN RDAP Service",
            title: `Established Domain (${Math.floor(ageDays / 365)} years old)`,
            snippet: `Registered on ${regDate.toISOString().split('T')[0]}`,
            evidence_text: `Domain has been registered for ${ageDays} days.`,
            evidence_strength: "MEDIUM",
            status: "VERIFIED",
            severity: "INFO",
            verified: true,
            confidence: 90.0,
          });
          score_modifier += 15;
        }
      }

      if (expEvent?.eventDate) {
        data.expiration_date = expEvent.eventDate;
      }
    }
  } catch {
    // RDAP query skipped or timed out
  }

  // 4. Lookalike & Typosquatting Analysis (with Leetspeak & Subword Tokenization)
  const leetNormalizedDomain = domain
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/@/g, 'a')
    .replace(/vv/g, 'w');

  for (const major of MAJOR_TECH_DOMAINS) {
    const majorBase = major.split('.')[0];
    const targetBase = domain.split('.')[0];
    const targetLeetBase = leetNormalizedDomain.split('.')[0];
    const targetTokens = targetBase.split(/[-_.]/);
    const targetLeetTokens = targetLeetBase.split(/[-_.]/);

    const isMatch = domain !== major && (
      domain.includes(majorBase) ||
      leetNormalizedDomain.includes(majorBase) ||
      targetTokens.some(tok => calculateLevenshteinDistance(tok, majorBase) <= 2) ||
      targetLeetTokens.some(tok => tok === majorBase || calculateLevenshteinDistance(tok, majorBase) <= 2) ||
      calculateLevenshteinDistance(targetBase, majorBase) <= 2
    );

    if (isMatch) {
      data.lookalike_detected = true;
      data.lookalike_target = major;

      evidence.push({
        category: "DOMAIN",
        evidence_type: "TYPOSQUATTING_LOOKALIKE",
        source_name: "Domain Similarity Analyzer",
        title: `Lookalike Domain Detected (Target: ${major})`,
        snippet: `Domain '${domain}' mimics prominent brand domain '${major}'.`,
        evidence_text: `Domain structure suggests brand impersonation targeting ${major}.`,
        evidence_strength: "VERY_STRONG",
        status: "NEGATIVE",
        severity: "CRITICAL",
        verified: true,
        confidence: 95.0,
      });
      score_modifier -= 40;
      break;
    }
  }

  // 5. VirusTotal API (if configured)
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey && !vtKey.includes('your-')) {
    try {
      const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
        headers: { 'x-apikey': vtKey },
        signal: AbortSignal.timeout(3500),
      });
      if (vtRes.ok) {
        const vtJson = await vtRes.json();
        const stats = vtJson.data?.attributes?.last_analysis_stats || {};
        const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
        data.virustotal_positives = malicious;

        if (malicious > 0) {
          evidence.push({
            category: "THREAT",
            evidence_type: "VIRUSTOTAL_FLAG",
            source_name: "VirusTotal Security Feeds",
            title: `Flagged by ${malicious} Security Vendors on VirusTotal`,
            snippet: `${malicious} security vendors classified this domain as malicious or suspicious.`,
            evidence_text: `VirusTotal domain report returned ${malicious} positive flags.`,
            evidence_strength: "VERY_STRONG",
            status: "NEGATIVE",
            severity: "CRITICAL",
            verified: true,
            confidence: 95.0,
          });
          score_modifier -= 35;
        } else {
          evidence.push({
            category: "THREAT",
            evidence_type: "VIRUSTOTAL_CLEAN",
            source_name: "VirusTotal Security Feeds",
            title: "Clean VirusTotal Reputation",
            snippet: "0 malicious vendor detections across 90+ security engines.",
            evidence_text: "VirusTotal domain report returned 0 positive threat flags.",
            evidence_strength: "STRONG",
            status: "VERIFIED",
            severity: "INFO",
            verified: true,
            confidence: 90.0,
          });
          score_modifier += 10;
        }
      }
    } catch {
      // VirusTotal call failed or timed out
    }
  }

  return { data, evidence, score_modifier };
}
