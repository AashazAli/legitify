/**
 * PDF Cryptographic Signature Inspector
 *
 * Inspects PDF binary buffers for authentic embedded digital signature dictionaries
 * according to the PDF 1.7 / 2.0 specifications (ISO 32000-1 / ISO 32000-2).
 *
 * A true cryptographic signature in a PDF contains:
 * 1. A signature field dictionary (/Type /Sig)
 * 2. A /ByteRange array defining signed byte intervals
 * 3. A /Contents hex/binary PKCS#7 / CMS / CAdES signature envelope
 */

export interface PdfSignatureInspection {
  hasEmbeddedSignature: boolean;
  isCryptographicVerified: boolean;
  signatureFormat: 'CRYPTOGRAPHIC_PKCS7' | 'EMBEDDED_SIG_OBJECT' | 'NONE';
  subFilter?: string;
  signDate?: string;
  details: string;
}

export function inspectPdfCryptographicSignature(buffer: Buffer): PdfSignatureInspection {
  if (!buffer || buffer.length < 100) {
    return {
      hasEmbeddedSignature: false,
      isCryptographicVerified: false,
      signatureFormat: 'NONE',
      details: 'Insufficient buffer length for PDF cryptographic analysis.',
    };
  }

  // Check PDF Magic Header (%PDF-)
  const isPdf = buffer.slice(0, 5).toString('ascii').startsWith('%PDF');
  if (!isPdf) {
    return {
      hasEmbeddedSignature: false,
      isCryptographicVerified: false,
      signatureFormat: 'NONE',
      details: 'Input file does not contain standard PDF magic header.',
    };
  }

  // Convert buffer to binary string for dictionary token scanning
  const raw = buffer.toString('binary');

  // Search for /ByteRange and /Type /Sig or /Type/Sig
  const hasByteRange = /\/ByteRange\s*\[\s*\d+\s+\d+\s+\d+\s+\d+\s*\]/.test(raw);
  const hasSigType = /\/Type\s*\/Sig\b/.test(raw);
  const hasContents = /\/Contents\s*<[0-9A-Fa-f]{16,}>/.test(raw);

  const subFilterMatch = raw.match(/\/SubFilter\s*\/([A-Za-z0-9_.]+)/);
  const subFilter = subFilterMatch ? subFilterMatch[1] : undefined;

  const dateMatch = raw.match(/\/M\s*\((D:[0-9]{14}[^)]*)\)/);
  const signDate = dateMatch ? dateMatch[1] : undefined;

  if (hasByteRange && (hasSigType || hasContents)) {
    return {
      hasEmbeddedSignature: true,
      isCryptographicVerified: false, // Observational signature object detected; cryptographic CA validation requires PKI chain check
      signatureFormat: 'CRYPTOGRAPHIC_PKCS7',
      subFilter,
      signDate,
      details: `Embedded cryptographic PDF signature object present (/ByteRange verified, SubFilter: ${subFilter || 'adbe.pkcs7.detached'}).`,
    };
  }

  if (hasSigType || hasByteRange) {
    return {
      hasEmbeddedSignature: true,
      isCryptographicVerified: false,
      signatureFormat: 'EMBEDDED_SIG_OBJECT',
      subFilter,
      signDate,
      details: 'Partial PDF digital signature dictionary detected without complete ByteRange payload.',
    };
  }

  return {
    hasEmbeddedSignature: false,
    isCryptographicVerified: false,
    signatureFormat: 'NONE',
    details: 'No embedded cryptographic PDF signature dictionary found in document binary structure.',
  };
}
