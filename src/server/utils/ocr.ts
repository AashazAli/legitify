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
    official_seal_detected: false,
    letterhead_logo_detected: false,
    font_consistency_score: 95,
    formatting_anomalies: [],
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

      const response = await client.models.generateContent({
        model: 'gemini-3.6-flash',
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
4. Financial clauses: Is there any registration fee, security deposit, laptop charge, or training fee?

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

      const responseText = response.text?.trim() || '';
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
          if (Array.isArray(parsed.emails)) detectedEmails.push(...parsed.emails);
          if (Array.isArray(parsed.fees_detected)) detectedFees.push(...parsed.fees_detected);
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
    if (!visualForensics.signature_detected && (lower.includes("authorized signatory") || lower.includes("sincerely") || lower.includes("hr manager") || lower.includes("director"))) {
      visualForensics.signature_detected = true;
      visualForensics.signature_type = "PRINTED_NAME";
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
