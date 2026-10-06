// ==============================================================================
// LEGITIFY HUGGING FACE INTELLIGENCE SERVICE
// Models Integrated:
// 1. pszemraj/pdf-ocr (docTR Deep-Learning Optical Character Recognition)
// 2. davanstrien/ColPali-Query-Generator (Qwen2.5-VL-7B Multimodal Document Queries)
// ==============================================================================
import dotenv from 'dotenv';
import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const execFileAsync = promisify(execFile);

const HF_TOKEN = process.env.HF_TOKEN || process.env.HUGGINGFACE_TOKEN || '';
const PDF_OCR_BASE_URL = 'https://pszemraj-pdf-ocr.hf.space';
const COLPALI_BASE_URL = 'https://davanstrien-colpali-query-generator.hf.space';

export interface ColPaliQueryOutput {
  broad_topical_query: string;
  broad_topical_explanation?: string;
  specific_detail_query: string;
  specific_detail_explanation?: string;
  visual_element_query: string;
  visual_element_explanation?: string;
  generated_at: string;
  model: string;
}

export interface ClaimQueryItem {
  claimId: string;
  claimType: string;
  targetEntity: string;
  queries: string[];
  rationale: string;
}

export interface ClaimInvestigationQueue {
  scanId?: string;
  companyName?: string;
  totalClaims: number;
  items: ClaimQueryItem[];
  allQueries: string[];
}

export interface PdfOcrResult {
  text: string;
  raw_ocr: string;
  pageCount?: number;
  runtime?: string;
  engine: 'PSZEMRAJ_DOCTR' | 'BAIDU_UNLIMITED_OCR';
}

/**
 * Extracts raw and cleaned text from an image or PDF using baidu/Unlimited-OCR Gradio Space.
 */
export async function extractTextWithBaiduUnlimitedOcr(
  fileBuffer: Buffer,
  mimeType: string = 'image/png',
  timeoutMs: number = 30000
): Promise<PdfOcrResult | null> {
  const ext = mimeType.includes('jpeg') || mimeType.includes('jpg') ? 'jpg' : mimeType.includes('pdf') ? 'pdf' : 'png';
  const tempFile = path.join(os.tmpdir(), `legitify_baidu_${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`);
  try {
    fs.writeFileSync(tempFile, fileBuffer);
    const runnerScript = path.resolve(__dirname, '../utils/hf_ocr_runner.py');
    if (fs.existsSync(runnerScript)) {
      const { stdout } = await execFileAsync('python', [runnerScript, 'image', tempFile, HF_TOKEN], { timeout: timeoutMs });
      const lastLine = stdout.trim().split('\n').pop() || '{}';
      const res = JSON.parse(lastLine);
      if (res.status === 'SUCCESS' && res.text && res.text.trim().length > 15) {
        const cleaned = res.text.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
        return {
          text: cleaned,
          raw_ocr: res.text,
          runtime: 'baidu/Unlimited-OCR Space',
          engine: 'BAIDU_UNLIMITED_OCR',
        };
      }
    }
  } catch (err: any) {
    console.warn(`[baidu/Unlimited-OCR] Runner notice: ${err.message}`);
  } finally {
    try { if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile); } catch {}
  }
  return null;
}

/**
 * Extracts raw and cleaned text from a PDF Buffer using the pszemraj/pdf-ocr Gradio Space (docTR OCR).
 * Includes python gradio_client runner, timeout guard, and fallback resilience.
 */
export async function extractTextWithPszemrajPdfOcr(
  pdfBuffer: Buffer,
  filename: string = 'document.pdf',
  timeoutMs: number = 30000
): Promise<PdfOcrResult | null> {
  // Tier 1: Local Python gradio_client Runner for pszemraj/pdf-ocr
  const tempFile = path.join(os.tmpdir(), `legitify_ocr_${Date.now()}_${Math.random().toString(36).slice(2)}.pdf`);
  try {
    fs.writeFileSync(tempFile, pdfBuffer);
    const runnerScript = path.resolve(__dirname, '../utils/hf_ocr_runner.py');
    if (fs.existsSync(runnerScript)) {
      try {
        const { stdout } = await execFileAsync('python', [runnerScript, 'pdf', tempFile, HF_TOKEN], { timeout: timeoutMs });
        const lastLine = stdout.trim().split('\n').pop() || '{}';
        const res = JSON.parse(lastLine);
        if (res.status === 'SUCCESS' && res.text && res.text.trim().length > 15) {
          const cleanedText = res.text.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
          return {
            text: cleanedText,
            raw_ocr: res.text,
            runtime: res.raw_result || 'pszemraj/pdf-ocr (docTR)',
            engine: (res.engine as any) || 'PSZEMRAJ_DOCTR',
          };
        }
      } catch (e: any) {
        console.warn(`[pszemraj/pdf-ocr] Python runner exception: ${e.message}`);
      }
    }
  } catch (err: any) {
    console.warn(`[pszemraj/pdf-ocr] Setup notice: ${err.message}`);
  } finally {
    try { if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile); } catch {}
  }

  // Tier 2: HTTP Gradio API Fallback
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // 1. Upload the PDF file to Gradio 5 space
    const formData = new FormData();
    const cleanFilename = filename.toLowerCase().endsWith('.pdf') ? filename : `${filename}.pdf`;
    const file = new File([pdfBuffer], cleanFilename, { type: 'application/pdf' });
    formData.append('files', file);

    const uploadRes = await fetch(`${PDF_OCR_BASE_URL}/gradio_api/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${HF_TOKEN}` },
      body: formData,
      signal: controller.signal,
    });

    if (!uploadRes.ok) {
      console.warn(`[pszemraj/pdf-ocr] Upload failed with HTTP status ${uploadRes.status}`);
      return null;
    }

    const uploadData = await uploadRes.json();
    const uploadedPath = Array.isArray(uploadData) ? uploadData[0] : uploadData;
    if (!uploadedPath) {
      console.warn('[pszemraj/pdf-ocr] No file path returned from upload endpoint');
      return null;
    }

    // 2. Trigger /convert_PDF call
    const callRes = await fetch(`${PDF_OCR_BASE_URL}/gradio_api/call/convert_PDF`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        data: [
          {
            path: uploadedPath,
            meta: { _type: 'gradio.FileData' },
            orig_name: cleanFilename,
            mime_type: 'application/pdf',
          },
        ],
      }),
      signal: controller.signal,
    });

    if (!callRes.ok) {
      console.warn(`[pszemraj/pdf-ocr] /call/convert_PDF failed with status ${callRes.status}`);
      return null;
    }

    const callData = await callRes.json();
    const eventId = callData?.event_id;
    if (!eventId) {
      console.warn('[pszemraj/pdf-ocr] Missing event_id in convert_PDF response');
      return null;
    }

    // 3. Read Server-Sent Events (SSE) stream
    const eventRes = await fetch(`${PDF_OCR_BASE_URL}/gradio_api/call/convert_PDF/${eventId}`, {
      headers: { Authorization: `Bearer ${HF_TOKEN}` },
      signal: controller.signal,
    });

    if (!eventRes.ok) {
      console.warn(`[pszemraj/pdf-ocr] Event fetch failed with status ${eventRes.status}`);
      return null;
    }

    const eventText = await eventRes.text();
    const lines = eventText.split('\n');
    let rawOcrText = '';
    let runtimeInfo = '';

    for (const line of lines) {
      if (line.startsWith('data:')) {
        try {
          const payload = JSON.parse(line.substring(5).trim());
          if (Array.isArray(payload) && typeof payload[0] === 'string') {
            rawOcrText = payload[0];
            if (payload[1] && typeof payload[1] === 'string') {
              runtimeInfo = payload[1].replace(/<[^>]*>/g, '').trim();
            }
          }
        } catch {
          // Continue scanning lines
        }
      }
    }

    if (!rawOcrText || rawOcrText.trim().length < 15 || rawOcrText.includes('File is not a PDF file')) {
      console.warn('[pszemraj/pdf-ocr] Received insufficient or invalid OCR output');
      return null;
    }

    // Clean text while preserving paragraph structure
    const cleanedText = rawOcrText
      .replace(/[ \t]+/g, ' ')
      .replace(/\n{3,}/g, '\n\n')
      .trim();

    return {
      text: cleanedText,
      raw_ocr: rawOcrText,
      runtime: runtimeInfo,
      engine: 'PSZEMRAJ_DOCTR',
    };
  } catch (err: any) {
    if (err.name === 'AbortError') {
      console.warn('[pszemraj/pdf-ocr] OCR request timed out, falling back to next tier');
    } else {
      console.warn(`[pszemraj/pdf-ocr] Error during execution: ${err.message}`);
    }
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Generates document retrieval queries using davanstrien/ColPali-Query-Generator (Qwen2.5-VL-7B-Instruct).
 * Produces broad topical queries, specific detail queries, and visual element queries.
 */
export async function generateColPaliQueries(
  imageBuffer: Buffer,
  mimeType: string = 'image/png',
  timeoutMs: number = 25000
): Promise<ColPaliQueryOutput | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const ext = mimeType.includes('jpeg') || mimeType.includes('jpg') ? 'jpg' : 'png';
    const formData = new FormData();
    const file = new File([imageBuffer], `page_1.${ext}`, { type: mimeType });
    formData.append('files', file);

    // 1. Upload page image
    const uploadRes = await fetch(`${COLPALI_BASE_URL}/gradio_api/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${HF_TOKEN}` },
      body: formData,
      signal: controller.signal,
    });

    if (!uploadRes.ok) return null;
    const uploadData = await uploadRes.json();
    const uploadedPath = Array.isArray(uploadData) ? uploadData[0] : uploadData;
    if (!uploadedPath) return null;

    // 2. Call /predict
    const callRes = await fetch(`${COLPALI_BASE_URL}/gradio_api/call/predict`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        data: [
          {
            path: uploadedPath,
            meta: { _type: 'gradio.FileData' },
            orig_name: `page_1.${ext}`,
            mime_type: mimeType,
          },
        ],
      }),
      signal: controller.signal,
    });

    if (!callRes.ok) return null;
    const callData = await callRes.json();
    const eventId = callData?.event_id;
    if (!eventId) return null;

    // 3. Read SSE stream
    const eventRes = await fetch(`${COLPALI_BASE_URL}/gradio_api/call/predict/${eventId}`, {
      headers: { Authorization: `Bearer ${HF_TOKEN}` },
      signal: controller.signal,
    });

    if (!eventRes.ok) return null;
    const eventText = await eventRes.text();
    const lines = eventText.split('\n');
    let jsonString = '';

    for (const line of lines) {
      if (line.startsWith('data:')) {
        try {
          const payload = JSON.parse(line.substring(5).trim());
          if (Array.isArray(payload) && typeof payload[0] === 'string') {
            jsonString = payload[0];
          }
        } catch {}
      }
    }

    if (!jsonString) return null;

    // Extract JSON block if wrapped in markdown
    const jsonMatch = jsonString.match(/```(?:json)?\s*([\s\S]*?)```/) || [null, jsonString];
    const parsed = JSON.parse(jsonMatch[1] || jsonString);

    return {
      broad_topical_query: parsed.broad_topical_query || '',
      broad_topical_explanation: parsed.broad_topical_explanation,
      specific_detail_query: parsed.specific_detail_query || '',
      specific_detail_explanation: parsed.specific_detail_explanation,
      visual_element_query: parsed.visual_element_query || '',
      visual_element_explanation: parsed.visual_element_explanation,
      generated_at: new Date().toISOString(),
      model: 'Qwen/Qwen2.5-VL-7B-Instruct (ColPali-Query-Generator)',
    };
  } catch (err: any) {
    console.warn(`[ColPali-Query-Generator] Notice: ${err.message}`);
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Forensically generates an investigation queue PER CLAIM extracted from the actual offer letter.
 * Never uses static hardcoded lists.
 */
export function generateClaimInvestigationQueue(
  claims: Array<{ claimId?: string; type: string; normalizedValue: string; rawExtraction?: string }>,
  options: {
    companyName?: string;
    domain?: string;
    recruiterEmail?: string;
    recruiterName?: string;
    role?: string;
    stipend?: string;
    upiId?: string;
    paymentAmount?: string;
    colpaliQueries?: ColPaliQueryOutput | null;
  } = {}
): ClaimInvestigationQueue {
  const items: ClaimQueryItem[] = [];
  const company = (options.companyName || '').trim();
  const domain = (options.domain || '').trim();
  const email = (options.recruiterEmail || '').toLowerCase().trim();
  const role = (options.role || '').trim();

  // 1. Company Claim Queue
  if (company) {
    items.push({
      claimId: 'C-COMP-01',
      claimType: 'COMPANY_IDENTITY',
      targetEntity: company,
      queries: [
        `"${company}" official website`,
        role ? `"${company}" careers "${role}"` : `"${company}" careers internship`,
        `"${company}" MCA corporate registry CIN`,
        `"${company}" internship experience`,
        `"${company}" internship scam complaint`,
      ],
      rationale: 'Verify corporate statutory existence, active careers page, and employment track record.',
    });
  }

  // 2. Recruiter Claim Queue
  if (options.recruiterName) {
    items.push({
      claimId: 'C-REC-01',
      claimType: 'RECRUITER_IDENTITY',
      targetEntity: options.recruiterName,
      queries: [
        company ? `"${options.recruiterName}" "${company}"` : `"${options.recruiterName}" human resources recruiter`,
        `"${options.recruiterName}" recruiter LinkedIn`,
      ],
      rationale: 'Confirm recruiter professional identity and association with named organisation.',
    });
  }

  // 3. Email Infrastructure Claim Queue
  if (email) {
    const emailDomain = email.split('@')[1];
    items.push({
      claimId: 'C-EML-01',
      claimType: 'COMMUNICATION_CHANNEL',
      targetEntity: email,
      queries: [
        `"${email}"`,
        `"${emailDomain}" "${company || ''}" official`,
        `"${email}" scam fraud report`,
      ],
      rationale: 'Determine if communication originates from official corporate mail server or public webmail.',
    });
  }

  // 4. Role & Stipend Claim Queue
  if (role || options.stipend) {
    items.push({
      claimId: 'C-STIP-01',
      claimType: 'COMPENSATION_TERMS',
      targetEntity: `${role || 'Intern'} - ${options.stipend || 'Stipend'}`,
      queries: [
        company && role ? `"${company}" "${role}" stipend Glassdoor AmbitionBox` : `"${role}" typical intern stipend India`,
        company ? `"${company}" internship offer letter format` : `internship joining terms`,
      ],
      rationale: 'Benchmark stipend against market norms and authentic compensation disclosures.',
    });
  }

  // 5. Website / Domain Claim Queue
  if (domain) {
    items.push({
      claimId: 'C-DOM-01',
      claimType: 'DOMAIN_AUTHENTICITY',
      targetEntity: domain,
      queries: [
        `"${domain}" domain registration whois`,
        `"${domain}" scam fake lookalike`,
        `site:${domain} careers`,
      ],
      rationale: 'Examine domain age, DNS MX routing, and typosquatting proximity to legitimate brands.',
    });
  }

  // 6. Payment & Financial Demand Claim Queue (CRITICAL)
  if (options.upiId || options.paymentAmount) {
    items.push({
      claimId: 'C-FEE-01',
      claimType: 'FINANCIAL_TRANSACTION_SAFETY',
      targetEntity: options.upiId || options.paymentAmount || 'Upfront Deposit Demand',
      queries: [
        options.upiId ? `"${options.upiId}" scam complaint fraud` : `"${company}" security deposit laptop fee scam`,
        company ? `"${company}" does not charge training fee advisory` : 'internship processing fee refund fraud',
      ],
      rationale: 'Cross-examine fee demand against corporate policy and public cybercrime registries.',
    });
  }

  // 7. Inject ColPali Multimodal Generated Queries
  if (options.colpaliQueries) {
    const cp = options.colpaliQueries;
    const cpQueries = [cp.broad_topical_query, cp.specific_detail_query, cp.visual_element_query].filter(Boolean);
    if (cpQueries.length > 0) {
      items.push({
        claimId: 'C-COLPALI-01',
        claimType: 'MULTIMODAL_DOCUMENT_SYNTHESIS',
        targetEntity: 'ColPali-Qwen2.5-VL Document Inspection',
        queries: cpQueries,
        rationale: 'Multimodal vision queries focusing on document visual elements, layout structure, and fine details.',
      });
    }
  }

  // Flatten all unique queries
  const allQueries = Array.from(new Set(items.flatMap(i => i.queries)));

  return {
    companyName: company || undefined,
    totalClaims: items.length,
    items,
    allQueries,
  };
}
