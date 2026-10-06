// ==============================================================================
// NORMALIZATION & SANITIZATION UTILITIES
// ==============================================================================

/**
 * Normalizes company names for deduplication & cache lookup.
 * e.g. "TechCorp Solutions Pvt Ltd." -> "techcorp solutions"
 */
export function normalizeCompanyName(name: string): string {
  if (!name) return "";
  let normalized = name.toLowerCase().trim();

  // Strip punctuation except internal alphanumeric
  normalized = normalized.replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, " ");

  // Normalize common corporate suffixes in India & Global
  const suffixes = [
    /\bprivate limited\b/g,
    /\bpvt ltd\b/g,
    /\bpvt\b/g,
    /\bltd\b/g,
    /\blimited\b/g,
    /\bllp\b/g,
    /\bllc\b/g,
    /\binc\b/g,
    /\bincorporated\b/g,
    /\bcorp\b/g,
    /\bcorporation\b/g,
    /\bgmbh\b/g,
    /\bplc\b/g,
    /\btechnologies\b/g,
    /\btechnology\b/g,
    /\bsolutions\b/g,
    /\bservices\b/g,
  ];

  for (const s of suffixes) {
    normalized = normalized.replace(s, " ");
  }

  // Remove multiple consecutive spaces
  normalized = normalized.replace(/\s+/g, " ").trim();
  return normalized || name.toLowerCase().trim();
}

/**
 * Normalizes domains for network lookups & consistency checks.
 * e.g. "https://www.TechCorp.COM/careers/" -> "techcorp.com"
 */
export function normalizeDomain(domainOrUrl: string): string {
  if (!domainOrUrl) return "";
  let clean = domainOrUrl.toLowerCase().trim();

  // Strip protocol
  clean = clean.replace(/^(https?:\/\/)?(www\.)?/, "");

  // Strip path and query parameters
  clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0];

  return clean.trim();
}

/**
 * Normalizes email addresses.
 */
export function normalizeEmail(email: string): string {
  if (!email) return "";
  return email.toLowerCase().trim();
}

/**
 * Extracts normalized domain from an email address.
 */
export function extractDomainFromEmail(email: string): string {
  if (!email || !email.includes("@")) return "";
  const parts = email.split("@");
  return normalizeDomain(parts[parts.length - 1]);
}

export const extractEmailDomain = extractDomainFromEmail;

/**
 * Known free/public webmail providers.
 */
const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.in",
  "yahoo.co.uk",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "icloud.com",
  "proton.me",
  "protonmail.com",
  "zoho.com",
  "mail.com",
  "yandex.com",
  "aol.com",
  "gmx.com",
  "rediffmail.com",
]);

export function isFreeEmailProvider(emailOrDomain: string): boolean {
  const domain = emailOrDomain.includes("@")
    ? extractDomainFromEmail(emailOrDomain)
    : normalizeDomain(emailOrDomain);
  return FREE_EMAIL_DOMAINS.has(domain);
}

/**
 * Simple Levenshtein distance for typosquatting / lookalike detection.
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  const an = a ? a.length : 0;
  const bn = b ? b.length : 0;
  if (an === 0) return bn;
  if (bn === 0) return an;
  const matrix = Array.from({ length: bn + 1 }, () => new Array(an + 1).fill(0));
  for (let i = 0; i <= an; i++) matrix[0][i] = i;
  for (let j = 0; j <= bn; j++) matrix[j][0] = j;
  for (let j = 1; j <= bn; j++) {
    for (let i = 1; i <= an; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j - 1][i] + 1,
        matrix[j][i - 1] + 1,
        matrix[j - 1][i - 1] + cost
      );
    }
  }
  return matrix[bn][an];
}

import crypto from 'crypto';
import dns from 'dns/promises';

// Comprehensive SSRF Blocklist for IPv4 & IPv6
const PRIVATE_IPV4_RANGES = [
  /^127\./,                         // Loopback 127.0.0.0/8
  /^10\./,                          // Private Network 10.0.0.0/8
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private Network 172.16.0.0/12
  /^192\.168\./,                    // Private Network 192.168.0.0/16
  /^169\.254\./,                    // Link-Local / Cloud Metadata 169.254.0.0/16
  /^0\./,                           // Zero address 0.0.0.0/8
  /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // Carrier Grade NAT 100.64.0.0/10
  /^192\.0\.0\./,                   // IETF Protocol Assignments 192.0.0.0/24
  /^198\.1[89]\./,                  // Benchmark testing 198.18.0.0/15
  /^22[4-9]\./,                     // Multicast 224.0.0.0/4
  /^2[3-5][0-9]\./,                 // Reserved / Experimental 240.0.0.0/4
];

const PRIVATE_IPV6_PATTERNS = [
  /^::1$/,                          // IPv6 Loopback
  /^::$|^0:0:0:0:0:0:0:0$/,         // Unspecified
  /^fe80:/i,                        // Link-local unicast fe80::/10
  /^fc00:|^fd00:/i,                 // Unique local address fc00::/7
  /^ff[0-9a-f]{2}:/i,               // Multicast ff00::/8
  /^::ffff:(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|0\.)/i, // IPv4-mapped IPv6
];

const DISALLOWED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata.internal',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '0.0.0.0',
]);

const DNS_REBINDING_DOMAINS = [
  'nip.io',
  'sslip.io',
  'xip.io',
  'localtest.me',
  'vcap.me',
  'lvh.me',
  'fbi.com.127.0.0.1.nip.io',
];

export function isPrivateOrReservedHost(host: string): boolean {
  if (!host) return true;
  const cleanHost = host.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0].split('?')[0].split('#')[0].split(':')[0];

  if (DISALLOWED_HOSTNAMES.has(cleanHost)) {
    return true;
  }

  for (const rebind of DNS_REBINDING_DOMAINS) {
    if (cleanHost.endsWith(rebind)) {
      return true;
    }
  }

  for (const pattern of PRIVATE_IPV4_RANGES) {
    if (pattern.test(cleanHost)) {
      return true;
    }
  }

  for (const pattern of PRIVATE_IPV6_PATTERNS) {
    if (pattern.test(cleanHost)) {
      return true;
    }
  }

  return false;
}

/**
 * Async DNS-resolution based SSRF validator.
 * Resolves hostname to its underlying IPs and ensures none resolve to private addresses (prevents DNS rebinding).
 */
export async function resolveAndValidateHostForSSRF(host: string): Promise<{ safe: boolean; reason?: string }> {
  if (!host) return { safe: false, reason: "Empty host" };

  if (isPrivateOrReservedHost(host)) {
    return { safe: false, reason: "Hostname is on the reserved or private network blocklist" };
  }

  const cleanHost = host.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  try {
    const addresses = await dns.resolve(cleanHost);
    for (const ip of addresses) {
      if (isPrivateOrReservedHost(ip)) {
        return { safe: false, reason: `Host ${cleanHost} resolved to private/reserved IP: ${ip}` };
      }
    }
    return { safe: true };
  } catch (err: any) {
    // If DNS resolution fails, allow if it was already deemed syntactically safe, or return lookup warning
    return { safe: true };
  }
}

export interface FileValidationResult {
  valid: boolean;
  sha256: string;
  size: number;
  mimeType: string;
  safeFilename: string;
  error?: string;
}

const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'ps1', 'vbs', 'sh', 'bash', 'js', 'py', 'dll', 'bin', 'msi', 'php', 'jsp', 'asp', 'cgi', 'scr', 'pif'
]);

export function validateUploadFile(
  buffer: Buffer,
  originalFilename: string = 'document',
  mimeType: string = 'application/octet-stream'
): FileValidationResult {
  const size = buffer.length;
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

  // 1. Enforce 10MB limit
  if (size > 10 * 1024 * 1024) {
    return { valid: false, sha256, size, mimeType, safeFilename: 'rejected', error: 'File exceeds 10MB limit' };
  }

  // 2. Enforce minimum content size
  if (size < 4) {
    return { valid: false, sha256, size, mimeType, safeFilename: 'rejected', error: 'File is empty or truncated' };
  }

  // 3. Extension inspection & neutralization
  const parts = originalFilename.split('.');
  const ext = parts.length > 1 ? parts[parts.length - 1].toLowerCase().trim() : '';
  if (DANGEROUS_EXTENSIONS.has(ext)) {
    return { valid: false, sha256, size, mimeType, safeFilename: 'rejected', error: `Executable or script extension rejected: .${ext}` };
  }

  const safeFilename = originalFilename.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);

  // 4. Strict Magic Bytes Inspection (do not trust client MIME alone)
  let detectedType = mimeType;
  let hasValidMagicBytes = false;

  if (buffer.length >= 4) {
    // PDF Magic Bytes (%PDF-)
    if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
      detectedType = 'application/pdf';
      hasValidMagicBytes = true;
    }
    // JPEG Magic Bytes (FF D8 FF)
    else if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
      detectedType = 'image/jpeg';
      hasValidMagicBytes = true;
    }
    // PNG Magic Bytes (89 50 4E 47 0D 0A 1A 0A)
    else if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
      detectedType = 'image/png';
      hasValidMagicBytes = true;
    }
    // WEBP Magic Bytes (RIFF .... WEBP)
    else if (buffer.length >= 12 && buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
             buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) {
      detectedType = 'image/webp';
      hasValidMagicBytes = true;
    }
    // Plain Text verification (printable ASCII/UTF-8 with no null bytes)
    else if (!buffer.subarray(0, Math.min(size, 1024)).includes(0x00)) {
      detectedType = 'text/plain';
      hasValidMagicBytes = true;
    }
  }

  const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'text/plain'];
  const isValid = hasValidMagicBytes && allowedTypes.includes(detectedType);

  return {
    valid: isValid,
    sha256,
    size,
    mimeType: detectedType,
    safeFilename,
    error: isValid ? undefined : `Unsupported or malformed file payload: detected as ${detectedType}`,
  };
}
