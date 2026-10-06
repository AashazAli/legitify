// ==============================================================================
// THREAT INTELLIGENCE & IOC SERVICE
// ==============================================================================
import { supabaseAdmin } from '../../lib/supabase/server';
import { EvidenceItem } from '../../types';

export interface ThreatMatch {
  indicator_type: string;
  indicator_value: string;
  threat_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  source: string;
  description: string;
}

// Suspicious recruitment phrase patterns commonly seen in fake internships
const FRAUD_PATTERNS = [
  {
    regex: /\b(registration\s*fee|training\s*fee|security\s*deposit|processing\s*fee|document\s*verification\s*fee|laptop\s*deposit)\b/i,
    type: "UPFRONT_FEE_REQUEST",
    severity: "CRITICAL" as const,
    description: "Requests upfront registration, security deposit, or training fee prior to commencement",
  },
  {
    regex: /\b(send\s*(money|payment|cash|crypto|usdt|bitcoin)|transfer\s*(amount|funds)|upi\s*id|gpay|phonepe|paytm)\b/i,
    type: "DIRECT_PAYMENT_DEMAND",
    severity: "CRITICAL" as const,
    description: "Demands direct UPI, wallet, or cryptocurrency transfer for job/internship offer",
  },
  {
    regex: /\b(whatsapp\s*me|contact\s*on\s*telegram|message\s*on\s*telegram|telegram\s*group|t\.me\/|wa\.me\/)\b/i,
    type: "COMMUNICATION_MIGRATION",
    severity: "HIGH" as const,
    description: "Attempts to migrate communication away from official channels to Telegram or WhatsApp",
  },
  {
    regex: /\b(urgent\s*joining|immediate\s*offer|no\s*interview\s*needed|direct\s*selection|offer\s*expires\s*in\s*\d+\s*(hours|minutes|hrs))\b/i,
    type: "URGENCY_MANIPULATION",
    severity: "MEDIUM" as const,
    description: "Uses artificial urgency or offers employment without genuine interview process",
  },
  {
    regex: /\b(share\s*otp|send\s*password|bank\s*account\s*pin|netbanking\s*credentials)\b/i,
    type: "CREDENTIAL_HARVESTING",
    severity: "CRITICAL" as const,
    description: "Requests OTP, bank PIN, or private login credentials",
  }
];

import { isPrivateOrReservedHost } from '../utils/normalizer';

export interface ThreatData {
  matches: ThreatMatch[];
  count: number;
  max_severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  sources_checked: string[];
  known_threat?: boolean;
  indicators?: any[];
}

export async function checkThreatIndicators(
  entityValue: string | string[],
  entityType: string = "generic",
  contextText: string = ""
): Promise<{ data: ThreatData; matches: ThreatMatch[]; evidence: EvidenceItem[] }> {
  const matches: ThreatMatch[] = [];
  const evidence: EvidenceItem[] = [];
  const sourcesChecked: string[] = ["Internal Threat IOC DB", "Behavioral Pattern Engine"];
  const values = (Array.isArray(entityValue) ? entityValue : [entityValue]).filter(Boolean).map(v => v.toLowerCase().trim());

  // 1. Query Database for verified Threat Indicators
  for (const normalized of values) {
    try {
      const { data: dbIndicators } = await supabaseAdmin
        .from('threat_indicators')
        .select('*')
        .or(`normalized_value.eq.${normalized},indicator_value.ilike.%${normalized}%`)
        .limit(10);

      if (dbIndicators && dbIndicators.length > 0) {
        for (const ind of dbIndicators) {
          matches.push({
            indicator_type: ind.indicator_type,
            indicator_value: ind.indicator_value,
            threat_type: ind.threat_type,
            severity: ind.severity,
            source: ind.source,
            description: ind.description,
          });

          evidence.push({
            category: "THREAT",
            evidence_type: "IOC_MATCH",
            source_name: ind.source || "Threat Intelligence Feed",
            title: `Known Threat Indicator: ${ind.threat_type}`,
            snippet: ind.description,
            evidence_text: `Entity matches verified threat record [${ind.indicator_value}] logged under ${ind.threat_type}.`,
            evidence_strength: "VERY_STRONG",
            status: "NEGATIVE",
            severity: ind.severity,
            verified: true,
            confidence: ind.confidence || 95.0,
          });
        }
      }
    } catch {
      // Database fallback handled gracefully
    }
  }

  // 2. Pattern Matching on Text Context (e.g. email or document body)
  const hasFeeNegation = /(?:no\s+(?:registration|application|training|processing|security)\s+fee|never\s+charge|free\s+of\s+charge|no\s+payment\s+is\s+required|not\s+require\s+(?:any\s+)?fee)/i.test(contextText);

  if (contextText) {
    for (const pattern of FRAUD_PATTERNS) {
      if ((pattern.type === "UPFRONT_FEE_REQUEST" || pattern.type === "DIRECT_PAYMENT_DEMAND") && hasFeeNegation) {
        continue;
      }
      if (pattern.regex.test(contextText)) {
        matches.push({
          indicator_type: "PATTERN",
          indicator_value: pattern.type,
          threat_type: pattern.type,
          severity: pattern.severity,
          source: "Heuristic Pattern Engine",
          description: pattern.description,
        });

        evidence.push({
          category: "THREAT",
          evidence_type: "SCAM_PATTERN_DETECTED",
          source_name: "Behavioral Heuristics",
          title: `Suspicious Pattern: ${pattern.type.replace(/_/g, ' ')}`,
          snippet: pattern.description,
          evidence_text: `Text content triggered risk rule for ${pattern.description}.`,
          evidence_strength: pattern.severity === "CRITICAL" ? "STRONG" : "MEDIUM",
          status: "WARNING",
          severity: pattern.severity,
          verified: false,
          confidence: 85.0,
        });
      }
    }
  }

  // 3. Live VirusTotal Threat Reputation Check (Domain / URL)
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey && vtKey.length > 20) {
    sourcesChecked.push("VirusTotal v3 Intelligence");
    const domainCandidates = values.filter(v => v.includes('.') && !v.includes(' ') && !isPrivateOrReservedHost(v));
    for (const dom of domainCandidates.slice(0, 2)) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1400);
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${dom}`, {
          headers: { 'x-apikey': vtKey },
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (vtRes.ok) {
          const vtData: any = await vtRes.json();
          const stats = vtData.data?.attributes?.last_analysis_stats;
          if (stats && (stats.malicious > 0 || stats.suspicious > 1)) {
            matches.push({
              indicator_type: "DOMAIN_REPUTATION",
              indicator_value: dom,
              threat_type: "VIRUSTOTAL_MALICIOUS_FLAG",
              severity: stats.malicious >= 3 ? "CRITICAL" : "HIGH",
              source: "VirusTotal Live API",
              description: `VirusTotal flagged domain with ${stats.malicious} malicious detections and ${stats.suspicious} suspicious ratings.`,
            });
            evidence.push({
              category: "THREAT",
              evidence_type: "VIRUSTOTAL_FLAG",
              source_name: "VirusTotal Global Threat Feed",
              title: `VirusTotal Security Flag: ${stats.malicious} Detections`,
              snippet: `Domain ${dom} flagged as malicious by global antivirus security engines.`,
              evidence_text: `Live VirusTotal analysis reported ${stats.malicious} malicious engines and ${stats.suspicious} suspicious ratings.`,
              evidence_strength: "VERY_STRONG",
              status: "NEGATIVE",
              severity: stats.malicious >= 3 ? "CRITICAL" : "HIGH",
              verified: true,
              confidence: 96.0,
            });
          }
        }
      } catch {}
    }
  }

  // 4. Live Google Safe Browsing Lookup
  const sbKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.SAFE_BROWSING_API_KEY;
  if (sbKey && sbKey.startsWith('AIzaSy')) {
    sourcesChecked.push("Google Safe Browsing");
    const urlCandidates = values.filter(v => v.includes('.') && !isPrivateOrReservedHost(v)).map(v => v.startsWith('http') ? v : `https://${v}`);
    if (urlCandidates.length > 0) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1400);
        const sbRes = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${sbKey}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: "legitify-threat-engine", clientVersion: "1.2.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: urlCandidates.slice(0, 3).map(url => ({ url })),
            }
          }),
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (sbRes.ok) {
          const sbData: any = await sbRes.json();
          if (sbData.matches && sbData.matches.length > 0) {
            for (const match of sbData.matches) {
              matches.push({
                indicator_type: "URL_THREAT",
                indicator_value: match.threat?.url || urlCandidates[0],
                threat_type: match.threatType,
                severity: "CRITICAL",
                source: "Google Safe Browsing",
                description: `Google Safe Browsing identified URL as ${match.threatType} (Phishing / Deceptive).`,
              });
              evidence.push({
                category: "THREAT",
                evidence_type: "SAFE_BROWSING_MATCH",
                source_name: "Google Safe Browsing",
                title: `Safe Browsing Match: ${match.threatType}`,
                snippet: `URL identified as deceptive / social engineering infrastructure.`,
                evidence_text: `Google Safe Browsing matched entity against active threat feeds under ${match.threatType}.`,
                evidence_strength: "VERY_STRONG",
                status: "NEGATIVE",
                severity: "CRITICAL",
                verified: true,
                confidence: 98.0,
              });
            }
          }
        }
      } catch {}
    }
  }

  // 5. Live AbuseIPDB IP Abuse Check
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  if (abuseKey && abuseKey.length > 20) {
    sourcesChecked.push("AbuseIPDB Global Feed");
    const ipCandidates = values.filter(v => /^(\d{1,3}\.){3}\d{1,3}$/.test(v) && !isPrivateOrReservedHost(v));
    for (const ip of ipCandidates.slice(0, 2)) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1400);
        const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
          headers: {
            'Key': abuseKey,
            'Accept': 'application/json',
          },
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (abuseRes.ok) {
          const abuseData: any = await abuseRes.json();
          const score = abuseData.data?.abuseConfidenceScore || 0;
          if (score > 20) {
            matches.push({
              indicator_type: "IP_ABUSE_SCORE",
              indicator_value: ip,
              threat_type: "ABUSEIPDB_HIGH_ABUSE_CONFIDENCE",
              severity: score > 75 ? "CRITICAL" : "HIGH",
              source: "AbuseIPDB Live API",
              description: `AbuseIPDB reported ${score}% abuse confidence score with ${abuseData.data?.totalReports || 0} malicious reports.`,
            });
            evidence.push({
              category: "THREAT",
              evidence_type: "IP_ABUSE_FLAG",
              source_name: "AbuseIPDB Intelligence Feed",
              title: `IP Flagged for Abuse: ${score}% Confidence`,
              snippet: `IP address ${ip} flagged across global cybersecurity reporting networks.`,
              evidence_text: `Live AbuseIPDB check returned ${score}% confidence with ${abuseData.data?.totalReports || 0} distinct threat reports.`,
              evidence_strength: "VERY_STRONG",
              status: "NEGATIVE",
              severity: score > 75 ? "CRITICAL" : "HIGH",
              verified: true,
              confidence: 94.0,
            });
          }
        }
      } catch {}
    }
  }

  let maxSeverity: ThreatData["max_severity"] = "INFO";
  if (matches.some(m => m.severity === "CRITICAL")) maxSeverity = "CRITICAL";
  else if (matches.some(m => m.severity === "HIGH")) maxSeverity = "HIGH";
  else if (matches.some(m => m.severity === "MEDIUM")) maxSeverity = "MEDIUM";
  else if (matches.some(m => m.severity === "LOW")) maxSeverity = "LOW";

  const hasVerifiedThreat = matches.some(m => m.source !== "Heuristic Pattern Engine" && (m.severity === "CRITICAL" || m.severity === "HIGH"));

  const data: ThreatData = {
    matches,
    count: matches.length,
    max_severity: maxSeverity,
    sources_checked: sourcesChecked,
    known_threat: hasVerifiedThreat,
  };

  return { data, matches, evidence };
}
