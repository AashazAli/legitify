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

export interface VisualForensicResult {
  regions: VisualRegion[];
  signatoryState: SignatoryVerificationState;
  signatoryName?: string;
  signatoryTitle?: string;
  signatoryDepartment?: string;
  signatureType: VisualSignatureType;
  evidence: EvidenceItem[];
  detectionMethod: 'GEMINI_VISION' | 'TEXT_PATTERN' | 'NONE';
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
  let detectionMethod: 'GEMINI_VISION' | 'TEXT_PATTERN' | 'NONE' = 'NONE';

  // Tier 1: Gemini Multimodal Vision analysis
  if (aiClient && (mimeType.startsWith('image/') || mimeType === 'application/pdf')) {
    try {
      const base64Data = buffer.toString('base64');
      const prompt = `
You are a forensic visual document examiner. Inspect this document and return a JSON array of visual regions.
Do NOT transcribe the document. Only identify structural visual regions:
- SIGNATURE (handwritten signature, signature image, or visual signoff block)
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
          regions = parsed.map((p: any) => ({
            type: (p.type as VisualRegionType) || 'SIGNATURE',
            page: Number(p.page) || 1,
            confidence: typeof p.confidence === 'number' ? Math.min(1.0, Math.max(0.1, p.confidence)) : 0.75,
            nearbyText: p.nearbyText ? String(p.nearbyText).trim() : undefined,
            evidenceId: generateVisualEvidenceId(scanId, Number(p.page) || 1, p.type || 'VIS'),
            detectionMethod: 'GEMINI_VISION' as const,
          }));
          if (regions.length > 0) {
            detectionMethod = 'GEMINI_VISION';
          }
        }
      }
    } catch (err) {
      // Vision model fallback to text pattern
    }
  }

  // Tier 2: OCR text pattern fallback if vision produced no signature regions
  if (!regions.some(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK') && ocrText) {
    const signaturePatterns = /(?:authorized\s+signatory|authorized\s+sign|yours\s+(?:sincerely|faithfully|truly)|hr\s+manager|head\s+-?\s*hr|director|talent\s+acquisition)[\s\S]{0,120}/i;
    const match = ocrText.match(signaturePatterns);
    if (match) {
      const nearbyText = match[0].trim();
      const evidenceId = generateVisualEvidenceId(scanId, 1, 'SIG');
      regions.push({
        type: 'SIGNATORY_BLOCK',
        page: 1,
        confidence: 0.65,
        nearbyText,
        evidenceId,
        detectionMethod: 'TEXT_PATTERN',
      });
      if (detectionMethod === 'NONE') {
        detectionMethod = 'TEXT_PATTERN';
      }
    }
  }

  // Determine signature type: Separate visual signature from cryptographic digital signature
  let signatureType: VisualSignatureType = 'ABSENT';
  let signatoryName: string | undefined;
  let signatoryTitle: string | undefined;
  let signatoryDepartment: string | undefined;

  const sigRegion = regions.find(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK');
  const stampRegion = regions.find(r => r.type === 'STAMP' || r.type === 'SEAL');

  if (sigRegion) {
    // Default to VISUAL_SIGNATURE (never CRYPTOGRAPHIC_SIGNATURE without certificate validation)
    signatureType = 'VISUAL_SIGNATURE';

    if (sigRegion.nearbyText) {
      const cleaned = sigRegion.nearbyText
        .replace(/authorized\s+signatory|authorized\s+sign|yours\s+(?:sincerely|faithfully|truly)/gi, '')
        .trim();
      const lines = cleaned.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      for (const line of lines) {
        const isCorporate = /(?:limited|ltd|private|pvt|company|corp|solutions|technologies|systems|enterprises|holdings|group)/i.test(line);
        const nameMatch = line.match(/^([A-Z](?:\.[A-Z]\.|\.|[a-z]+)?(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/);
        if (nameMatch && !signatoryName && !isCorporate) {
          signatoryName = nameMatch[1];
        } else if (/(?:manager|director|lead|head|officer|partner|executive|acquisition)/i.test(line) && !signatoryTitle) {
          signatoryTitle = line;
        } else if (/(?:human\s+resources|hr|talent|operations|engineering)/i.test(line) && !signatoryDepartment) {
          signatoryDepartment = line;
        }
      }
    }
  } else if (stampRegion) {
    signatureType = 'STAMP';
  }

  // Determine state machine
  const signatoryState = determineSignatoryState(regions, signatoryName);

  // Generate non-boosting evidence items
  const evidence = generateEvidenceItems(regions, signatoryState, signatureType, signatoryName, signatoryTitle, scanId);

  return {
    regions,
    signatoryState,
    signatoryName,
    signatoryTitle,
    signatoryDepartment,
    signatureType,
    evidence,
    detectionMethod,
    analysisVersion: 'LEGITIFY-VISUAL-FORENSICS-v2.0',
  };
}

export function determineSignatoryState(
  regions: VisualRegion[],
  signatoryName?: string
): SignatoryVerificationState {
  const hasSignature = regions.some(r => r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK' || r.type === 'STAMP');

  if (!hasSignature) {
    return 'NO_SIGNATURE_DETECTED';
  }

  if (hasSignature && signatoryName) {
    // Observed in document, but NOT independently verified against corporate signatory roll
    return 'SIGNATORY_OBSERVED';
  }

  if (hasSignature && !signatoryName) {
    return 'SIGNATURE_PRESENT_UNIDENTIFIED';
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
  scanId: string
): EvidenceItem[] {
  const items: EvidenceItem[] = [];

  for (const r of regions) {
    const isSig = r.type === 'SIGNATURE' || r.type === 'SIGNATORY_BLOCK';
    const isSeal = r.type === 'STAMP' || r.type === 'SEAL';
    const isLogo = r.type === 'LOGO' || r.type === 'LETTERHEAD';

    let title = `Visual Element Detected: ${r.type}`;
    let snippet = `Detected ${r.type} on page ${r.page} (${Math.round(r.confidence * 100)}% visual confidence).`;
    let evidenceText = `Visual examination identified ${r.type} on page ${r.page}. Detection method: ${r.detectionMethod}.`;

    if (isSig) {
      title = `Visual Signature Observed (Page ${r.page})`;
      snippet = signatoryName
        ? `Visual signature observed with signatory reference: ${signatoryName}${signatoryTitle ? ` (${signatoryTitle})` : ''}.`
        : `Visual signature mark observed without clear printed signatory name.`;
      evidenceText = `Visual document forensics identified a ${signatureType.toLowerCase().replace('_', ' ')} on page ${r.page}. ` +
        `Signatory status: ${signatoryState}. Note: Visual presence of a signature mark is an observational artifact and does not independently prove corporate authorization or authenticity.`;
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
      },
    });
  }

  return items;
}
