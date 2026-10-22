// ==============================================================================
// MULTI-TIER DEEP FORENSIC OCR & VISUAL ANALYZER
// ==============================================================================
import { GoogleGenAI } from '@google/genai';
import { createWorker } from 'tesseract.js';
import { VisualForensicsData } from '../../types';

let tesseractWorker: any = null;

async function getWorker() {
  if (!tesseractWorker) {
    tesseractWorker = await createWorker('eng');
  }
  return tesseractWorker;
}

export interface DeepForensicAnalysisResult {
  raw_text: string;
  visual_forensics: VisualForensicsData;
  detected_company?: string;
  detected_emails: string[];
  detected_signatory?: string;
  detected_fees: string[];
  has_seal: boolean;
  has_signature: boolean;
}

export async function extractTextFromImage(
  buffer: Buffer,
  mimeType: string = 'image/jpeg'
): Promise<string> {
  const result = await analyzeDocumentDeepForensics(buffer, mimeType);
  return result.raw_text;
}

export async function analyzeDocumentDeepForensics(
  buffer: Buffer,
  mimeType: string = 'image/jpeg'
): Promise<DeepForensicAnalysisResult> {
  const isPdf = mimeType === 'application/pdf' || (buffer.length > 4 && buffer.toString('utf-8', 0, 4) === '%PDF');
  const normalizedMime = isPdf ? 'application/pdf' : (mimeType === 'image/jpg' ? 'image/jpeg' : mimeType);

  let rawText = "";
  const visualForensics: VisualForensicsData = {
    signature_detected: false,
    signature_type: "ABSENT",
    signatory_state: "NO_SIGNATURE_DETECTED",
    official_seal_detected: false,
    letterhead_logo_detected: false,
    font_consistency_score: 95,
    formatting_anomalies: [],
    visual_regions: [],
    evidence_ids: [],
  };

  const detectedEmails: string[] = [];
  const detectedFees: string[] = [];
  let detectedCompany: string | undefined;
  let detectedSignatory: string | undefined;

  // Tier 1: Gemini 3.6 Flash Multimodal Deep Forensic Analysis
  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_KEY || process.env.VITE_GEMINI_API_KEY;
  if (apiKey && !apiKey.includes('your-')) {
    try {
      const client = new GoogleGenAI({ apiKey });
      const base64Data = buffer.toString('base64');

      let response: any;
      const candidateModels = [
        process.env.GEMINI_MODEL || 'gemini-3.6-flash',
        'gemini-2.5-flash',
        'gemini-1.5-flash'
      ];

      for (const m of candidateModels) {
        try {
          response = await client.models.generateContent({
            model: m,
            contents: [
              {
                role: 'user',
                parts: [
                  {
                    inlineData: {
                      mimeType: normalizedMime || 'application/pdf',
                      data: base64Data,
                    },
                  },
                  {
                    text: `You are an elite forensic document analyst. Deeply inspect this document image/PDF.
Extract:
1. Complete verbatim transcription of every single line, word, number, date, and character.
2. Visual forensics: Is there a signature? (digital/handwritten/printed), Signatory name & designation, Is there an official company seal/stamp? Is there a letterhead logo?
3. Recruiter contact: Email address, HR name, phone number.
4. Financial clauses: Is there any registration fee, caution deposit, security deposit, booking amount, interview-slot charge, service charge, laptop charge, or training fee? If any fee, charge, deposit, or payment is demanded from the candidate, list it in "fees_detected".

Return JSON format:
{
  "transcription": "...",
  "signature_detected": boolean,
  "signature_type": "DIGITAL_STAMP" | "HANDWRITTEN_IMAGE" | "PRINTED_NAME" | "ABSENT" | "SUSPICIOUS",
  "signatory_name": "...",
  "signatory_title": "...",
  "official_seal_detected": boolean,
  "letterhead_logo_detected": boolean,
  "company_name": "...",
  "emails": ["..."],
  "fees_detected": ["..."]
}`,
                  },
                ],
              },
            ],
          });
          if (response?.text) break;
        } catch (mErr: any) {
          console.warn(`[Forensics] Gemini model ${m} failed, trying next:`, mErr?.message || mErr);
        }
      }

      const responseText = response?.text?.trim() || '';
      try {
        const jsonMatch = responseText.match(/\{.*\}/s);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          rawText = parsed.transcription || responseText;
          visualForensics.signature_detected = parsed.signature_detected ?? (responseText.toLowerCase().includes("signature") || responseText.toLowerCase().includes("signatory"));
          visualForensics.signature_type = parsed.signature_type || (visualForensics.signature_detected ? "HANDWRITTEN_IMAGE" : "ABSENT");
          visualForensics.signatory_name = parsed.signatory_name;
          visualForensics.signatory_title = parsed.signatory_title;
          visualForensics.official_seal_detected = parsed.official_seal_detected ?? false;
          visualForensics.letterhead_logo_detected = parsed.letterhead_logo_detected ?? true;
          detectedCompany = parsed.company_name;
          detectedSignatory = parsed.signatory_name;
          if (Array.isArray(parsed.fees_detected)) {
            const genuineFees = parsed.fees_detected.filter((f: any) => {
              if (!f || typeof f !== 'string') return false;
              const clean = f.trim().toLowerCase();
              if (
                clean === 'none' || clean === 'n/a' || clean === 'nil' || clean === 'null' || clean === 'no' ||
                clean.includes('no fee') || clean.includes('not detected') || clean.includes('none detected') ||
                clean.includes('free of cost') || clean.includes('zero fee') || clean.includes('no registration') ||
                clean.includes('no deposit')
              ) {
                return false;
              }
              if (
                clean.includes('salary') || clean.includes('stipend') || clean.includes('ctc') ||
                clean.includes('remuneration') || clean.includes('package') || clean.includes('p.m.') ||
                clean.includes('per month') || clean.includes('lpa')
              ) {
                return false;
              }
              return true;
            });
            detectedFees.push(...genuineFees);
          }
        } else {
          rawText = responseText;
        }
      } catch {
        rawText = responseText;
      }
    } catch (err) {
      console.warn('[Forensics] Gemini Flash deep analysis failed, falling back to local extractor...', err);
    }
  }

  // Tier 2: Local Tesseract.js WASM OCR for image formats if text is still empty
  if (!rawText && !isPdf) {
    try {
      const worker = await getWorker();
      const ret = await worker.recognize(buffer);
      if (ret.data?.text && ret.data.text.trim().length > 10) {
        rawText = ret.data.text.trim();
      }
    } catch (err) {
      console.warn('[OCR] Local Tesseract attempt failed:', err);
    }
  }

  // Text-based fallback analysis
  if (rawText) {
    const lower = rawText.toLowerCase();
    const hasDigitalSig = /(?:digitally\s+signed|docusign|adobe\s+sign|signature\s+valid|esign|e-sign|cryptographic)/i.test(rawText);
    const hasSignatory = lower.includes("authorized signatory") || lower.includes("sincerely") || lower.includes("hr manager") || lower.includes("director") || lower.includes("talent acquisition");

    if (!visualForensics.signature_detected && (hasDigitalSig || hasSignatory)) {
      visualForensics.signature_detected = true;
      visualForensics.signature_type = hasDigitalSig ? "CRYPTOGRAPHIC_SIGNATURE" : "PRINTED_SIGNATURE";
      visualForensics.signatory_state = "SIGNATORY_OBSERVED";
    }

    if (!visualForensics.signatory_name || !detectedSignatory) {
      const sigPattern = /(?:digitally\s+signed\s+by[:\s]*|signed\s+by[:\s]*|sd\/-?\s*|yours\s+(?:sincerely|faithfully|truly)[,\s]*\n*|authorized\s+signatory[,\s]*\n*)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/i;
      const sigMatch = rawText.match(sigPattern);
      if (sigMatch && sigMatch[1] && !/(?:limited|ltd|pvt|private|corporation|technologies|solutions)/i.test(sigMatch[1])) {
        visualForensics.signatory_name = sigMatch[1].trim();
        detectedSignatory = sigMatch[1].trim();
      }
    }

    if (!visualForensics.signatory_title) {
      const titleMatch = rawText.match(/(?:director|vice\s+president|head\s+of\s+hr|hr\s+manager|talent\s+acquisition\s+lead|authorized\s+signatory)/i);
      if (titleMatch) {
        visualForensics.signatory_title = titleMatch[0].trim();
      }
    }

    if (!visualForensics.official_seal_detected && (lower.includes("seal") || lower.includes("stamp") || lower.includes("certified"))) {
      visualForensics.official_seal_detected = true;
    }
  }

  return {
    raw_text: rawText,
    visual_forensics: visualForensics,
    detected_company: detectedCompany,
    detected_emails: detectedEmails,
    detected_signatory: detectedSignatory,
    detected_fees: detectedFees,
    has_seal: visualForensics.official_seal_detected,
    has_signature: visualForensics.signature_detected,
  };
}
