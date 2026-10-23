import { GoogleGenAI } from '@google/genai';
import * as crypto from 'crypto';
import type {
  VisualRegion,
  VisualRegionType,
  VisualSignatureType,
  SignatoryVerificationState,
  VisualForensicsData,
  EvidenceItem,
} from '../../types';
import { inspectPdfCryptographicSignature } from '../utils/pdfSignature';

export interface VisualForensicResult {
  regions: VisualRegion[];
  signatoryState: SignatoryVerificationState;
  signatoryName?: string;
  signatoryTitle?: string;
  signatoryDepartment?: string;
  signatureType: VisualSignatureType;
  hasVisualSignatureMark: boolean;
  hasSignatoryBlock: boolean;
  hasSignatoryIdentity: boolean;
  hasCryptographicSignature: boolean;
  isCryptographicVerified: boolean;
  evidence: EvidenceItem[];
  detectionMethod: 'GEMINI_VISION' | 'TEXT_PATTERN' | 'PDF_METADATA' | 'NONE';
  analysisVersion: string;
}

const getGeminiClient = (): GoogleGenAI | null => {
  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({ apiKey });
};

export function generateVisualEvidenceId(scanId: string, page: number, type: string): string {
  const hash = crypto.createHash('sha256')
    .update(`${scanId}-${page}-${type}-${Date.now()}-${Math.random()}`)
    .digest('hex').substring(0, 6).toUpperCase();
  return `${scanId}-DOC-P${page}-${type.substring(0, 6)}-${hash}`;
}

/**
 * Detects visual regions (signatures, seals, stamps, letterheads, logos) in an uploaded document.
 * This runs independently from OCR text extraction.
 *
 * Core rule: Signature detected = OBSERVED EVIDENCE, never a trust boost.
 * A scammer can insert a signature image; absence of text signature is NOT proof of fraud.
 */
export async function detectVisualRegions(
  buffer: Buffer,
  mimeType: string,
  scanId: string,
  ocrText?: string
): Promise<VisualForensicResult> {
  const aiClient = getGeminiClient();
  let regions: VisualRegion[] = [];
  let detectionMethod: 'GEMINI_VISION' | 'TEXT_PATTERN' | 'PDF_METADATA' | 'NONE' = 'NONE';

  // Check authentic PDF cryptographic signature metadata
  const pdfInspection = inspectPdfCryptographicSignature(buffer);
  const hasCryptographicSignature = pdfInspection.hasEmbeddedSignature;
  const isCryptographicVerified = pdfInspection.isCryptographicVerified;

  if (hasCryptographicSignature) {
    const evidenceId = generateVisualEvidenceId(scanId, 1, 'CRYPTO_SIG');
    regions.push({
      type: 'DIGITAL_SIGNATURE',
      page: 1,
      confidence: 0.95,
      nearbyText: pdfInspection.details,
      evidenceId,
      detectionMethod: 'OCR_LAYOUT',
    });
    detectionMethod = 'PDF_METADATA';
  }

  // Tier 1: Gemini Multimodal Vision analysis
  if (aiClient && (mimeType.startsWith('image/') || mimeType === 'application/pdf')) {
    try {
      const base64Data = buffer.toString('base64');
      const prompt = `
You are a forensic visual document examiner. Inspect this document and return a JSON array of visual regions.
Do NOT transcribe the document. Only identify structural visual regions:
- SIGNATURE (handwritten signature, signature image, or pen-mark signoff)
- STAMP (ink stamp, rubber stamp, corporate seal)
- SEAL (embossed or digital seal)
- LOGO (corporate logo mark)
- LETTERHEAD (header block with logo/corporate identity)
- QR_CODE (scannable QR code)
- PHOTO (embedded photo)
- TABLE (data table)
- HANDWRITING (handwritten annotations)
- SIGNATORY_BLOCK (printed closing with person's name and title)

For each region provide:
- type: ONE OF ['SIGNATURE', 'STAMP', 'SEAL', 'LOGO', 'LETTERHEAD', 'QR_CODE', 'PHOTO', 'TABLE', 'HANDWRITING', 'SIGNATORY_BLOCK']
- page: 1-indexed integer
- confidence: number between 0.0 and 1.0
- nearbyText: short text immediately adjacent to the region (e.g. name/title next to signature)

Return ONLY valid JSON: [{"type": "...", "page": 1, "confidence": 0.9, "nearbyText": "..."}]
`;

      const response = await aiClient.models.generateContent({
        model: process.env.GEMINI_MODEL || 'gemini-3.6-flash',
        contents: [
          prompt,
          { inlineData: { data: base64Data, mimeType } }
        ]
      });

      const text = response.text || '';
      const jsonMatch = text.match(/\[\s*\{[\s\S]*\}\s*\]/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        if (Array.isArray(parsed)) {
          const visionRegions = parsed.map((p: any) => ({
            type: (p.type as VisualRegionType) || 'SIGNATURE',
            page: Number(p.page) || 1,
            confidence: typeof p.confidence === 'number' ? Math.min(1.0, Math.max(0.1, p.confidence)) : 0.75,
            nearbyText: p.nearbyText ? String(p.nearbyText).trim() : undefined,
            evidenceId: generateVisualEvidenceId(scanId, Number(p.page) || 1, p.type || 'VIS'),
            detectionMethod: 'GEMINI_VISION' as const,
          }));
          if (visionRegions.length > 0) {
            regions.push(...visionRegions);
            detectionMethod = 'GEMINI_VISION';
          }
        }
      }
    } catch {
      // Vision model fallback to text pattern
    }
  }

  // Tier 2: OCR text pattern fallback if vision produced no signature regions
  if (!regions.some(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK' || r.type === 'DIGITAL_SIGNATURE') && ocrText) {
    const signaturePatterns = /(?:digitally\s+signed|docusign|adobe\s+sign|signature\s+valid|esign|e-sign|authorized\s+signatory|authorized\s+sign|yours\s+(?:sincerely|faithfully|truly|warmly|regards)|with\s+regards|warm\s+regards|hr\s+manager|head\s+-?\s*hr|director|founder|talent\s+acquisition)[\s\S]{0,220}/i;
    const match = ocrText.match(signaturePatterns);
    if (match) {
      const nearbyText = match[0].trim();
      const isClaimedDigital = /(?:digitally\s+signed|docusign|adobe\s+sign|signature\s+valid|esign|e-sign)/i.test(nearbyText);
      const evidenceId = generateVisualEvidenceId(scanId, 1, isClaimedDigital ? 'DIGSIG' : 'SIG');
      regions.push({
        type: isClaimedDigital ? 'SIGNATORY_BLOCK' : 'SIGNATORY_BLOCK',
        page: 1,
        confidence: 0.85,
        nearbyText,
        evidenceId,
        detectionMethod: 'TEXT_PATTERN',
      });
      if (detectionMethod === 'NONE') {
        detectionMethod = 'TEXT_PATTERN';
      }
    }
  }

  // Determine signature-related elements independently
  const hasVisualSignatureMark = regions.some(r => r.type === 'SIGNATURE' || (r.type === 'HANDWRITING' && r.confidence >= 0.7));
  const hasStampOrSeal = regions.some(r => r.type === 'STAMP' || r.type === 'SEAL');
  const hasExplicitSignatoryBlock = regions.some(r => r.type === 'SIGNATORY_BLOCK' || r.type === 'DIGITAL_SIGNATURE') ||
    Boolean(ocrText && /(?:authorized\s+signatory|sincerely|faithfully|warm\s+regards|best\s+regards|with\s+regards|regards|for\s+[A-Za-z0-9\s&.,'-]+|human\s+resources\s+department)/i.test(ocrText));

  let signatoryName: string | undefined;
  let signatoryTitle: string | undefined;
  let signatoryDepartment: string | undefined;

  // Search text blocks across all closing sections and nearby visual regions
  const sigRegion = regions.find(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK' || r.type === 'DIGITAL_SIGNATURE');
  const searchBlocks = [
    sigRegion?.nearbyText,
    ocrText ? ocrText.slice(-800) : '',
    ocrText || '',
  ].filter(Boolean) as string[];

  const titleRegex = /(?:(?:Global\s+)?Head\s+(?:of\s+)?[-–\s]?\s*(?:Human\s+Resources|HR|Talent\s+Acquisition|Engineering(?:\s+Talent)?|People|Operations|Product|Design)|Chief\s+(?:Executive|Operating|Technology|People|Human\s+Resources|Financial|Revenue)\s+Officer|Vice\s+President(?:\s*[-–\s]\s*[A-Za-z\s]+)?|Managing\s+Director|Director(?:\s*[-–\s]\s*[A-Za-z\s]+)?|Founder(?:\s*(?:&|and)\s*Managing\s+Director)?|Co-Founder|Partner|Proprietor|Lead\s+AI\s+Scientist|Senior\s+(?:HR\s+Manager|Recruiter|Systems\s+Engineer)|HR\s+Manager|Talent\s+Acquisition(?:\s+(?:Partner|Lead|Specialist|Manager))?|Lead\s+Recruiter|Placement\s+Officer|Authorized\s+Signatory|VP\s+of\s+[A-Za-z\s]+)/i;

  const isGreetingOrPreamble = (str: string): boolean =>
    /^(?:dear|to|hi\b|hello\b|attn|attention|subject|sub|date|ref|offer|internship|appointment|letter\s+of)/i.test(str.trim());

  // Search candidate closing lines
  const docLines = (ocrText || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  let closingIndex = -1;
  for (let i = docLines.length - 1; i >= 0; i--) {
    if (/(?:sincerely|faithfully|regards|warm\s+regards|best\s+regards|with\s+regards|authorized\s+signatory|for\s+[A-Za-z0-9\s&.,'-]+|accepted\s+(?:and\s+agreed)?|signed\s+by)/i.test(docLines[i])) {
      closingIndex = i;
      break;
    }
  }

  const candidateLines = closingIndex >= 0 ? docLines.slice(closingIndex) : docLines.slice(-10);

  for (let i = 0; i < candidateLines.length; i++) {
    const line = candidateLines[i];
    if (isCorporateName(line) || isGreetingOrPreamble(line)) continue;

    // Check inline dash/hyphen: e.g. "Sudip Das — Founder", "Anita Roy - Head of HR"
    const inlineDash = line.match(/^([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){1,3})\s*(?:[—–\-]|,)\s*(.+)$/);
    if (inlineDash && !signatoryName) {
      const cand = inlineDash[1].trim();
      const candTitle = inlineDash[2].trim();
      if (!isCorporateName(cand) && !isGreetingOrPreamble(cand)) {
        signatoryName = cand;
        if (titleRegex.test(candTitle)) {
          signatoryTitle = candTitle;
        }
        continue;
      }
    }

    // Check standalone name
    const nameCand = line.match(/^([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){1,3})$/);
    if (nameCand && !signatoryName && !titleRegex.test(line) && !/department|resources|services|solutions|team|office/i.test(line)) {
      signatoryName = nameCand[1].trim();
      continue;
    }

    // Check standalone title (prefer specific role over generic 'Authorized Signatory')
    if (titleRegex.test(line) && (!signatoryTitle || signatoryTitle === 'Authorized Signatory')) {
      const titleMatch = line.match(titleRegex);
      if (titleMatch) {
        signatoryTitle = titleMatch[0].trim();
        continue;
      }
    }

    // Check department
    if (/(?:human\s+resources|talent\s+acquisition|people\s+operations|hiring\s+team)/i.test(line) && !signatoryDepartment) {
      signatoryDepartment = line.trim();
    }
  }

  // Also check nearby visual regions if provided
  for (const block of searchBlocks) {
    if (signatoryName && signatoryTitle) break;

    // Pattern B: Explicit labels: Name: Sudip Das, Designation: Founder
    if (!signatoryName) {
      const explicitMatch = block.match(/(?:Name|Signatory(?:\s*Name)?|Signed\s+By|Sd\/?-?)\s*[:\-]\s*(?:(?:Mr\.?|Ms\.?|Mrs\.?|Dr\.?)\s*)?([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){1,3})/i);
      if (explicitMatch && !isCorporateName(explicitMatch[1].trim()) && !isGreetingOrPreamble(explicitMatch[1].trim())) {
        signatoryName = explicitMatch[1].trim();
      }
    }
    if (!signatoryTitle) {
      const titleLabelMatch = block.match(/(?:Designation|Title|Role|Position)\s*[:\-]\s*([A-Za-z\s&/-]{3,40})/i);
      if (titleLabelMatch && titleRegex.test(titleLabelMatch[1].trim())) {
        signatoryTitle = titleLabelMatch[1].trim();
      }
    }
  }

  // Fallback title detection if name found but title unextracted
  if (signatoryName && !signatoryTitle && ocrText) {
    const rawTitleMatch = ocrText.match(titleRegex);
    if (rawTitleMatch) {
      signatoryTitle = rawTitleMatch[0].trim();
    }
  }

  // Department fallback detection
  if (!signatoryDepartment && ocrText) {
    const deptMatch = ocrText.match(/(?:Human\s+Resources(?:\s*&\s*Talent\s+Acquisition)?|Talent\s+Acquisition|People\s+Operations|Recruitment\s+Division)/i);
    if (deptMatch) {
      signatoryDepartment = deptMatch[0].trim();
    }
  }

  const hasSignatoryBlock = hasExplicitSignatoryBlock || Boolean(signatoryName) || Boolean(signatoryTitle) || Boolean(signatoryDepartment);
  const hasSignatoryIdentity = Boolean(signatoryName || signatoryTitle);

  // Determine signature format
  let signatureType: VisualSignatureType = 'ABSENT';
  if (hasCryptographicSignature) {
    signatureType = 'CRYPTOGRAPHIC_SIGNATURE';
  } else if (hasVisualSignatureMark) {
    signatureType = 'VISUAL_SIGNATURE';
  } else if (hasStampOrSeal) {
    signatureType = 'STAMP';
  } else if (signatoryName) {
    signatureType = 'PRINTED_SIGNATORY';
  } else if (hasSignatoryBlock) {
    signatureType = 'SIGNATORY_BLOCK';
  } else if (ocrText && ocrText.trim().length < 40) {
    signatureType = 'UNCERTAIN';
  } else {
    signatureType = 'ABSENT';
  }

  // Determine state machine
  const signatoryState = determineSignatoryState(regions, signatoryName, hasSignatoryBlock, hasVisualSignatureMark);

  // Generate non-boosting evidence items
  const evidence = generateEvidenceItems(
    regions,
    signatoryState,
    signatureType,
    signatoryName,
    signatoryTitle,
    scanId,
    hasVisualSignatureMark,
    hasCryptographicSignature
  );

  return {
    regions,
    signatoryState,
    signatoryName,
    signatoryTitle,
    signatoryDepartment,
    signatureType,
    hasVisualSignatureMark,
    hasSignatoryBlock,
    hasSignatoryIdentity,
    hasCryptographicSignature,
    isCryptographicVerified,
    evidence,
    detectionMethod,
    analysisVersion: 'LEGITIFY-VISUAL-FORENSICS-v2.1',
  };
}

function isCorporateName(str: string): boolean {
  return /(?:limited|ltd|private|pvt|company|corp|inc|llp|solutions|technologies|systems|enterprises|holdings|services|infotech|group|foundation)/i.test(str);
}

export function determineSignatoryState(
  regions: VisualRegion[],
  signatoryName?: string,
  hasSignatoryBlock?: boolean,
  hasVisualSignatureMark?: boolean
): SignatoryVerificationState {
  const hasSignatureRegion = regions.some(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK' || r.type === 'STAMP' || r.type === 'DIGITAL_SIGNATURE');

  if (!hasSignatureRegion && !hasSignatoryBlock && !signatoryName && !hasVisualSignatureMark) {
    return 'NO_SIGNATURE_DETECTED';
  }

  if (signatoryName) {
    // Signatory identity observed in document; visual presence does not verify against internal corporate registry
    return 'SIGNATORY_OBSERVED';
  }

  if (hasVisualSignatureMark || hasSignatureRegion) {
    return 'SIGNATURE_PRESENT_UNIDENTIFIED';
  }

  if (hasSignatoryBlock) {
    return 'SIGNATORY_BLOCK_OBSERVED';
  }

  return 'NO_SIGNATURE_DETECTED';
}

/**
 * Generates EvidenceItem records from visual forensics.
 * CRITICAL RULE: Signature presence is OBSERVED, never a positive trust boost.
 * Status is 'UNKNOWN' or 'INFO', verified is ALWAYS false.
 */
export function generateEvidenceItems(
  regions: VisualRegion[],
  signatoryState: SignatoryVerificationState,
  signatureType: VisualSignatureType,
  signatoryName: string | undefined,
  signatoryTitle: string | undefined,
  scanId: string,
  hasVisualSignatureMark?: boolean,
  hasCryptographicSignature?: boolean
): EvidenceItem[] {
  const items: EvidenceItem[] = [];

  for (const r of regions) {
    const isSig = r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK' || r.type === 'DIGITAL_SIGNATURE';
    const isSeal = r.type === 'STAMP' || r.type === 'SEAL';
    const isLogo = r.type === 'LOGO' || r.type === 'LETTERHEAD';

    let title = `Visual Element Detected: ${r.type}`;
    let snippet = `Detected ${r.type} on page ${r.page} (${Math.round(r.confidence * 100)}% visual confidence).`;
    let evidenceText = `Visual document examination identified ${r.type} on page ${r.page}. Detection method: ${r.detectionMethod}.`;

    if (isSig) {
      if (hasCryptographicSignature) {
        title = `Embedded Cryptographic Signature Object (Page ${r.page})`;
        snippet = `PDF document contains embedded digital signature dictionary. Validated structure against ISO 32000.`;
        evidenceText = `Cryptographic PDF dictionary inspection detected embedded /ByteRange signature. Observational analysis only.`;
      } else if (hasVisualSignatureMark) {
        title = `Visual Signature Mark Observed (Page ${r.page})`;
        snippet = signatoryName
          ? `Visual signature mark observed with signatory reference: ${signatoryName}${signatoryTitle ? ` (${signatoryTitle})` : ''}.`
          : `Visual signature mark observed without printed signatory name.`;
        evidenceText = `Visual document forensics identified a signature mark on page ${r.page}. ` +
          `Signatory status: ${signatoryState}. Note: Visual presence of a signature mark is an observational artifact and does not independently prove corporate authorization or authenticity.`;
      } else {
        title = `Printed Signatory Block Observed (Page ${r.page})`;
        snippet = signatoryName
          ? `Printed signatory authority designated: ${signatoryName}${signatoryTitle ? ` (${signatoryTitle})` : ''}.`
          : `Corporate signing authority block observed.`;
        evidenceText = `Sign-off authority block present on page ${r.page}. No visual handwritten or digital graphic signature mark detected.`;
      }
    } else if (isSeal) {
      title = `Corporate Stamp/Seal Observed (Page ${r.page})`;
      snippet = `Official seal or stamp graphic observed on page ${r.page}.`;
      evidenceText = `Visual document forensics identified a stamp/seal region on page ${r.page}. Visual observation only.`;
    } else if (isLogo) {
      title = `Corporate Letterhead/Logo Element (Page ${r.page})`;
      snippet = `Visual letterhead or branding mark identified on page ${r.page}.`;
      evidenceText = `Visual document forensics observed branding graphics on page ${r.page}.`;
    }

    items.push({
      id: r.evidenceId,
      scan_id: scanId,
      category: 'DOCUMENT',
      evidence_type: `VISUAL_${r.type}`,
      source_name: `Visual Document Forensics (${r.detectionMethod})`,
      title,
      snippet,
      evidence_text: evidenceText,
      claim: isSig ? `Document bears visual signature (${signatoryState})` : `Visual ${r.type} present`,
      evidence_strength: 'MEDIUM',
      status: 'UNKNOWN', // Observed, NOT verified
      severity: 'INFO',  // Informational, NEVER a positive trust boost
      verified: false,   // Visual observation != corporate verification
      confidence: Math.round(r.confidence * 100),
      collected_at: new Date().toISOString(),
      supporting_data: {
        page: r.page,
        type: r.type,
        detectionMethod: r.detectionMethod,
        signatoryName,
        signatoryTitle,
        signatoryState,
        signatureType,
        hasVisualSignatureMark: Boolean(hasVisualSignatureMark),
        hasCryptographicSignature: Boolean(hasCryptographicSignature),
      },
    });
  }

  return items;
}
