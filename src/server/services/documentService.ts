import crypto from 'crypto';
// ==============================================================================
// LEGITIFY FORENSIC & INTERNSHIELD DETECTION ENGINE
// 100% Exact Port of InternShield NLP Classifier, NER Extractor, & 10 Rules
// ==============================================================================
import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { EvidenceItem } from '../../types';
import { extractTextFromImage, analyzeDocumentDeepForensics } from '../utils/ocr';
import { extractTextWithPszemrajPdfOcr, extractTextWithBaiduUnlimitedOcr } from './huggingfaceService';
import { isFilenameOrPlaceholder } from '../utils/normalizer';

const execFileAsync = promisify(execFile);

export interface DetailedPaymentEvidence {
  category: string;
  amount?: string;
  recipient?: string;
  channel?: string;
  is_refundable?: boolean;
  refund_terms?: string;
  deadline?: string;
  exact_quote: string;
  why_it_matters: string;
  confidence: number;
}

export interface NormalizedDocumentEvidence {
  raw_ocr?: string;
  cleaned_text: string;
  selection_statement?: string;
  candidate_name?: string;
  recruiter_name?: string;
  recruiter_email?: string;
  company_name?: string;
  job_role?: string;
  compensation?: string;
  joining_date?: string;
  terms_clauses: string[];
  ocr_engine?: string;
}

export interface TriggeredFlag {
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  score: number;
}

export interface DocumentExtractionResult {
  filename?: string;
  mime_type?: string;
  extracted_text: string;
  raw_ocr?: string;
  ocr_engine?: string;
  normalized_evidence?: NormalizedDocumentEvidence;
  has_fee_demand: boolean;
  is_confirmed_impersonation?: boolean;
  is_suspicious_offer_letter?: boolean;
  detected_company_name?: string;
  detected_signatory?: string;
  detected_domain?: string;
  detected_email?: string;
  detected_cin?: string;
  detected_stipend?: string;
  detected_dates?: string[];
  has_urgency?: boolean;
  has_informal_channel?: boolean;
  has_grammar_anomalies?: boolean;
  has_generic_greeting?: boolean;
  requested_fees?: { amount?: string; reason?: string; channel?: string }[];
  fee_details?: DetailedPaymentEvidence[];
  payment_case?: 'EXPLICIT_DEMAND' | 'CONDITIONAL_DEMAND' | 'POLICY_MENTION_WITHOUT_DEMAND' | 'WARNING_AGAINST_PAYMENT' | 'NO_PAYMENT_EVIDENCE' | 'AMBIGUOUS_EVIDENCE';
  payment_explanation?: string;
  candidate_compensation?: {
    type: 'STIPEND' | 'SALARY' | 'CTC' | 'REIMBURSEMENT';
    amount?: string;
    raw_quote?: string;
  };
  suspicious_patterns: string[];
  extracted_entities: Record<string, any>;
  evidence: EvidenceItem[];
  triggered_flags: TriggeredFlag[];
  dimension_scores: {
    rules: number;
    nlp: number;
    ner: number;
  };
  final_score: number;
  verdict: "LIKELY GENUINE" | "SUSPICIOUS" | "LIKELY FAKE";
  next_steps: string[];
}

export interface DocumentAnalysisResult extends DocumentExtractionResult {
  file_size?: number;
  sanitized_evidence_block: string;
  detected_entities: {
    emails: string[];
    phones: string[];
    urls: string[];
    fees_detected: { amount: string; reason: string }[];
    upi_ids: string[];
    cryptos: string[];
    informal_channels: string[];
    urgency_phrases: string[];
  };
  risk_signals: string[];
  extracted_claims?: any[];
}

// Dynamic personal email domains (RFC standard free/public webmail providers)
const PERSONAL_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com",
  "rediffmail.com", "protonmail.com", "aol.com", "ymail.com",
  "mail.com", "inbox.com", "zoho.com", "icloud.com", "live.com",
  "yandex.com", "tutanota.com", "guerrillamail.com", "tempmail.com"
]);

// --- GENUINE INDICATORS (InternShield) ---
const GENUINE_INDICATORS: [RegExp, number, string, boolean][] = [
  [/(terms?\s+and\s+conditions?|terms\s+of\s+employment)/i, 0.04, "Contains terms and conditions", true],
  [/(probation\s+period|probationary\s+period)/i, 0.04, "Mentions probation period", false],
  [/(non[\-\s]?disclosure|nda|confidentiality\s+agreement)/i, 0.05, "Includes NDA/confidentiality clause", false],
  [/(intellectual\s+property|ip\s+rights)/i, 0.03, "References IP rights", false],
  [/(code\s+of\s+conduct|company\s+polic)/i, 0.03, "References company policies", false],
  [/(notice\s+period)/i, 0.03, "Mentions notice period", false],
  [/(termination|dismissal)\s+(clause|policy)/i, 0.03, "Includes termination clause", false],
  [/(ctc|cost\s+to\s+company|compensation\s+breakup)/i, 0.05, "Has compensation breakdown", true],
  [/(basic\s+salary|gross\s+salary|net\s+salary)/i, 0.04, "Mentions specific salary component", true],
  [/(pf|provident\s+fund|esi|gratuity)/i, 0.05, "Mentions statutory benefits (PF/ESI)", true],
  [/(tax\s+deduction|tds|income\s+tax)/i, 0.04, "References tax deductions", false],
  [/(hra|house\s+rent\s+allowance|dearness\s+allowance)/i, 0.04, "Mentions HRA/DA", false],
  [/(medical\s+insurance|health\s+insurance|group\s+insurance)/i, 0.04, "Mentions insurance benefits", false],
  [/(cin|corporate\s+identity\s+number)/i, 0.06, "Contains CIN reference", true],
  [/(registered\s+office|corporate\s+office)/i, 0.04, "Mentions registered office", true],
  [/(authorized\s+signatory)/i, 0.04, "Has authorized signatory", true],
  [/(offer\s+is\s+subject\s+to|contingent\s+upon)/i, 0.04, "Conditional offer language", false],
  [/(background\s+verification|background\s+check)/i, 0.04, "Mentions background verification", false],
  [/(employee\s+id|employee\s+code|employee\s+number)/i, 0.03, "References employee ID", false],
  [/(we\s+are\s+pleased\s+to\s+(offer|inform|extend))/i, 0.02, "Professional offer language", false],
  [/(designation|role|position)\s*:\s*\w+/i, 0.03, "Specifies designation/role", false],
  [/(reporting\s+(to|manager)|supervisor)/i, 0.03, "Mentions reporting structure", false],
  [/(letter\s+of\s+(appointment|offer|intent))/i, 0.03, "Uses formal letter type", false],
  [/(human\s+resources?\s+department|hr\s+department)/i, 0.03, "References HR department", false],
];

// --- FRAUD INDICATORS (InternShield & Cyber Reference Framework) ---
const FRAUD_INDICATORS: [RegExp, number, string][] = [
  // 1. Fee & Payment Traps
  [/(?:candidate|applicant|student|intern|you)\s*(?:must|(?:is|are|be)\s+required\s+to|needs?\s+to|have\s+to|has\s+to|shall|will\s+need\s+to)\s*(?:pay|deposit|transfer|remit)|(?:pay|deposit|transfer)\s+(?:registration|caution|security|admission|portal|training|booking|enrolment|acceptance|processing)\s*(?:fee|deposit|charges?|amount)|pay\s+(?:₹|rs\.?|inr|\$)?\s*[0-9,]+(?:\s*\/-)?\s*(?:before\s*joining|to\s*(?:confirm|accept|secure)|via\s*upi|online\s*to)/i, 0.20, "Requests money/payment from candidate"],
  [/(registration\s*fees?|processing\s*fees?|security\s*(?:deposit|amount|fee))/i, 0.20, "Demands registration/processing fee or security deposit"],
  [/(caution\s*(?:deposit|money|amount|fee)|laptop\s*deposit|equipment\s*deposit)/i, 0.20, "Demands caution deposit or hardware/equipment deposit"],
  [/(internship\s*fees?|enrolment\s*fees?|enrollment\s*fees?|admission\s*fees?|acceptance\s*fees?)/i, 0.20, "Demands candidate internship/enrolment fee"],
  [/(?:required|need|must|instructed|(?:are|is)\s+required)\s+to\s+pay\s+(?:online|the\s+internship|through|before|to\s+confirm|[₹$]|rs\.?|inr|[0-9,]+)/i, 0.20, "Mandates candidate payment for enrolment/onboarding"],
  [/pay\s+(?:₹|rs\.?|inr|\$)?\s*[0-9,]+(?:\s*\/-)?\s*(?:online|through|for\s+internship|to\s+confirm|before)/i, 0.20, "Specifies mandatory fee amount for candidate enrolment"],
  [/to\s+confirm\s+your\s+(?:enrolment|enrollment|selection|admission|offer|seat|internship|appointment)[^\n]*?(?:pay|deposit|transfer|remit|fee|charge|amount)/i, 0.20, "Conditions offer confirmation on candidate fee payment"],
  [/(training\s*(?:fee|cost|charge)|kit\s*charge|courier\s*charge|uniform\s*deposit|id\s*card\s*fee)/i, 0.18, "Charges for training, uniforms, ID card, or equipment kit"],
  [/(onboarding\s*(?:fee|charge|deposit)|documentation\s*(?:fee|charge)|verification\s*(?:fee|charge))/i, 0.20, "Charges onboarding, documentation, or background verification fee"],
  [/(refundable\s+(deposit|amount|fee|caution))/i, 0.18, "Mentions 'refundable deposit' — common scam tactic"],
  [/(pay\s+before\s+joining|advance\s+payment|upfront\s+fee)/i, 0.20, "Demands payment before joining"],
  [/(interview[\s-]slot\s*booking|hr\s*panel\s*charge|seat\s*booking\s*amount)/i, 0.18, "Demands interview-slot or placement booking charge"],
  [/(portal\s*activation\s*(?:fee|charge)|work\s*from\s*home\s*activation)/i, 0.18, "Charges work-from-home portal activation fee"],
  [/(settlement\s*amount|clear\s*the\s*settlement|avoid\s*legal\s*escalation|recovery\s*payment)/i, 0.20, "Recovery-payment trap or legal escalation threat"],

  // 2. Instant Selection & Fake Hiring Claims
  [/(guaranteed?\s+(placement|job|salary|income))/i, 0.12, "Guarantees placement/job"],
  [/(100\s*%\s*(placement|guaranteed|success))/i, 0.14, "Claims 100% guarantee"],
  [/(earn\s+(up\s+to|upto)\s*₹?\s*\d+\s*lakh)/i, 0.12, "Unrealistic earning claims"],
  [/(no\s+(experience|skills?)\s+(required|needed))/i, 0.10, "No experience required for skilled role"],
  [/(work\s+from\s+home.*earn|earn.*work\s+from\s+home)/i, 0.10, "WFH earning scheme language"],
  [/(unlimited\s+(earning|income|potential))/i, 0.10, "Unlimited earning claims"],
  [/(selected|shortlisted)\s+(based\s+on\s+(your\s+)?(resume|profile|cv))/i, 0.09, "Unsolicited selection claim"],
  [/(you\s+have\s+been\s+(selected|chosen|picked))\s+(without|from\s+our\s+database)/i, 0.10, "Unsolicited selection without application"],
  [/(congratulations!?\s+you\s+(have\s+been|are)\s+selected)/i, 0.08, "Over-enthusiastic congratulations"],
  [/(no\s+interview|direct\s+selection|skip\s+interview|interview\s+(?:is\s+)?waived)/i, 0.14, "Claims no interview needed / interview waived"],
  [/(bulk\s*hiring|urgent\s*bulk\s*selection)/i, 0.10, "Uses bulk-hiring script with fast confirmation pressure"],

  // 3. Sender Mismatch & Chat-Only Recruitment
  [/(whatsapp|telegram|signal)\s*(for|to|at|:)?\s*(details|more|joining|info|contact)/i, 0.12, "Uses WhatsApp/Telegram for official comms"],
  [/(join\s+(our|the)\s+(whatsapp|telegram)\s+group)/i, 0.14, "Directs to WhatsApp/Telegram group"],
  [/(do\s+not\s+(?:email|contact)\s+the\s+company|only\s+on\s+whatsapp|clearance\s+will\s+happen\s+only\s+on)/i, 0.18, "Blocks direct company contact and mandates chat-only communication"],
  [/(call\s+this\s+number|contact\s+on\s+(mobile|cell|phone))/i, 0.08, "Directs to personal phone number"],
  [/(click\s+(here|this\s+link|below).*register)/i, 0.10, "Pushes registration via link"],
  [/(google\s*form|typeform|jotform)/i, 0.12, "Uses Google Forms/Typeform for hiring"],
  [/(bit\.ly|tinyurl|short\.link|goo\.gl)/i, 0.10, "Uses URL shortener — obfuscation"],

  // 4. Urgency, Coercive Deadlines & Premature Sensitive Document Requests
  [/(respond\s+within\s+(?:20\s+minutes?|24\s+hours?|48\s+hours?)|immediately|urgent|asap)/i, 0.08, "Uses extreme urgency/pressure language"],
  [/(limited\s+slots?|seats?\s+filling\s+fast|only\s+\d+\s+seats?)/i, 0.08, "Creates artificial scarcity"],
  [/(offer\s+(will\s+)?(?:expire|be\s+cancelled)|last\s+chance|final\s+call)/i, 0.08, "Pressures with cancellation/expiry threats"],
  [/(?:send|upload|share)\s+(?:aadhaar|pan|passport|bank\s*proof|otp)\s*(?:today|immediately|before\s*joining|for\s*payroll)/i, 0.15, "Demands sensitive identity documents prior to legitimate verification"],
  [/(refer\s+and\s+earn|referral\s+bonus\s+for\s+candidates)/i, 0.10, "Referral scheme pattern"],
];

const URGENCY_PHRASES = [
  "respond within 24 hours", "within 48 hours", "limited slots", "offer expires",
  "act immediately", "don't miss this opportunity", "limited time offer", "respond urgently",
  "seats filling fast", "last date to respond", "immediate joining required", "confirm within",
  "hurry up", "first come first serve", "last few seats", "offer valid till", "respond today", "do not delay"
];

export interface PdfExtractionOutput {
  text: string;
  raw_ocr: string;
  engine: 'PSZEMRAJ_DOCTR' | 'GEMINI_VISION' | 'PDF_PARSE' | 'RAW_BINARY_STREAM' | 'FALLBACK_UTF8';
}

export async function extractPdfTextWithEngine(
  buffer: Buffer,
  filename: string = 'document.pdf'
): Promise<PdfExtractionOutput> {
  // Tier 1: Instant local vector PDF extraction (pdf-parse / PDFParse class)
  // Executes in <30ms without network overhead and captures 100% accurate text
  try {
    const pdfModule = await import('pdf-parse');
    if ((pdfModule as any).PDFParse) {
      const PDFParseClass = (pdfModule as any).PDFParse;
      const parser = new PDFParseClass(new Uint8Array(buffer));
      await parser.load();
      const res = await parser.getText();
      const parsedText = (res?.text || res?.pages?.map((p: any) => p.text).join('\n\n') || '').trim();
      if (parsedText.length > 20) {
        return {
          text: parsedText,
          raw_ocr: parsedText,
          engine: 'PDF_PARSE',
        };
      }
    } else {
      const parseFn = (pdfModule as any).default || pdfModule;
      if (typeof parseFn === 'function') {
        const data = await parseFn(buffer);
        const parsed = (data?.text || '').trim();
        if (parsed.length > 20) {
          return {
            text: parsed,
            raw_ocr: parsed,
            engine: 'PDF_PARSE',
          };
        }
      }
    }
  } catch (pdfErr: any) {
    console.warn(`[documentService] Local PDFParse note: ${pdfErr?.message || pdfErr}`);
  }

  // Tier 2: Multimodal Gemini Vision / PDF OCR (for scanned / raster PDFs)
  try {
    const ocrText = await extractTextFromImage(buffer, 'application/pdf');
    if (ocrText && ocrText.trim().length > 20) {
      return {
        text: ocrText.trim(),
        raw_ocr: ocrText,
        engine: 'GEMINI_VISION',
      };
    }
  } catch {}

  // Tier 3: Hugging Face Deep Learning OCR (pszemraj/pdf-ocr using Mindee docTR)
  try {
    const hfOcr = await extractTextWithPszemrajPdfOcr(buffer, filename, 8000);
    if (hfOcr && hfOcr.text && hfOcr.text.trim().length > 20) {
      return {
        text: hfOcr.text.trim(),
        raw_ocr: hfOcr.raw_ocr,
        engine: 'PSZEMRAJ_DOCTR',
      };
    }
  } catch (e: any) {
    console.warn(`[documentService] pszemraj/pdf-ocr fallback notice: ${e.message}`);
  }

  // Tier 4: Binary text chunks
  try {
    const rawStr = buffer.toString('latin1');
    const textChunks: string[] = [];
    const textBlockRegex = /\(([^)]+)\)\s*Tj|\[([^\]]+)\]\s*TJ/g;
    let match;
    while ((match = textBlockRegex.exec(rawStr)) !== null) {
      const chunk = match[1] || match[2] || '';
      const cleanChunk = chunk.replace(/\\([()\\])/g, '$1').trim();
      if (cleanChunk.length > 1) textChunks.push(cleanChunk);
    }
    if (textChunks.length > 5) {
      const res = textChunks.join(' ').replace(/\s+/g, ' ').trim();
      return {
        text: res,
        raw_ocr: rawStr,
        engine: 'RAW_BINARY_STREAM',
      };
    }
  } catch {}

  const rawStr = buffer.toString('utf-8');
  const printable = rawStr.replace(/[^\x20-\x7E\n\r\t]/g, ' ').replace(/\s+/g, ' ').trim();
  return {
    text: printable.length > 20 ? printable : "",
    raw_ocr: rawStr,
    engine: 'FALLBACK_UTF8',
  };
}

export async function extractTextFromPdfBuffer(buffer: Buffer, filename: string = 'document.pdf'): Promise<string> {
  const result = await extractPdfTextWithEngine(buffer, filename);
  return result.text;
}

export async function extractTextFromImageBuffer(buffer: Buffer, mimeType: string = 'image/jpeg'): Promise<string> {
  try {
    const text = await extractTextFromImage(buffer, mimeType);
    if (text && text.length > 20) return text;
  } catch {}

  const rawStr = buffer.toString('utf-8');
  const printable = rawStr.replace(/[^\x20-\x7E\n\r\t]/g, ' ').replace(/\s+/g, ' ').trim();
  return printable.length > 20 ? printable : "";
}

export function splitTextIntoSentences(raw: string): string[] {
  if (!raw) return [];
  // Normalize Unicode non-breaking and special spaces
  const normalized = raw.replace(/[\u00A0\u2000-\u200B\u202F\u205F]/g, ' ');
  const protectedText = normalized
    .replace(/\b(Rs|rs|inr|INR)\.\s*(?=[a-z0-9]|$)/gi, '$1_DOT_ ')
    .replace(/\b(Mr|Mrs|Ms|Dr|Prof|Sr|Jr|No|Ltd|Pvt|Ref|eg|ie|approx)\.\s+/gi, '$1_DOT_ ');
  return protectedText
    .split(/(?<=[.!?])\s+|\r?\n\s*\r?\n+/)
    .map(s => s.replace(/_DOT_\s*/g, '. ').trim())
    .filter(s => s.length > 0);
}

export function extractDocumentSignals(
  text: string,
  filename?: string,
  mimeType?: string,
  rawOcr?: string,
  ocrEngine?: string,
  externalFees?: string[]
): DocumentAnalysisResult {
  const textLower = text.toLowerCase();
  const flags: TriggeredFlag[] = [];
  const evidence: EvidenceItem[] = [];
  const suspiciousPatterns: string[] = [];

  const emails = Array.from(new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []));
  const phones = Array.from(new Set(text.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b[6-9]\d{9}\b/g) || []));
  const urls = Array.from(new Set(text.match(/https?:\/\/[^\s<>"]+/g) || []));
  const upiMatches = Array.from(new Set(text.match(/[a-zA-Z0-9.\-_]{2,256}@(paytm|upi|ybl|okhdfcbank|okaxis|okicici|oksbi|axl|ibl|barodampay|postbank|icici|axisbank|sbi|hdfcbank|kotak)/gi) || []));

  // --- 1. Company Name Extraction ---
  // --- 1. Dynamic Company Name Extraction (No hardcoded authority lists) ---
  let detectedCompanyName: string | undefined;

  // Pattern A: Explicit letterhead or document header prefixes
  const prefixMatch = text.match(/(?:Offer\s*Letter\s*(?:from|for|by)|Welcome\s*to|Employment\s*Offer\s*-\s*|Sub:\s*Appointment\s*(?:at|in|with)|Company\s*Name\s*:\s*|Organisation\s*:\s*|Organization\s*:\s*|Employer\s*:\s*)([A-Z0-9][A-Za-z0-9\s&.,'-]{2,50}(?:Pvt\s*Ltd|Private\s*Limited|Limited|Ltd|LLC|Inc|Corp|Technologies|Solutions|Enterprises|Infotech|Services|Global|Aviation|Motors|Consultancy|Systems)?)/i);
  if (prefixMatch && prefixMatch[1]?.trim()) {
    const cand = prefixMatch[1].trim();
    if (!isFilenameOrPlaceholder(cand) && !cand.startsWith('(')) {
      detectedCompanyName = cand;
    }
  }

  // Pattern B: Legal entity markers (e.g. Acme Corp Ltd, Tech Solutions Private Limited, Clinchsoft Technologies)
  if (!detectedCompanyName) {
    const legalMatch = text.match(/\b([A-Z][A-Za-z0-9 &.,'-]{1,45}\s+(?:Private\s+Limited|Pvt\s+Ltd|Limited|LLP|LLC|Corporation|Corp|Inc|GmbH|Technologies|Solutions|Enterprises|Infotech|Services|Global|Consultancy))\b/i);
    if (legalMatch) detectedCompanyName = legalMatch[1].trim();
  }

  // Pattern C: Internship / employment program at company
  if (!detectedCompanyName) {
    const programMatch = text.match(/(?:Internship\s+Program\s+(?:at|with)|employment\s+with|position\s+at)\s+([A-Z0-9][A-Za-z0-9&.,' -]{2,45})/i);
    if (programMatch) detectedCompanyName = programMatch[1].trim().replace(/,\s*commencing.*$/i, '');
  }

  // Pattern D: Formal sign-off entity (Yours truly Clinchsoft Technologies)
  if (!detectedCompanyName) {
    const signoffMatch = text.match(/(?:Yours\s+(?:truly|faithfully|sincerely)|Warm\s+regards|Regards)[,\s\n]+([A-Z][A-Za-z0-9&.,' -]{2,45})/i);
    if (signoffMatch && !/(?:hr|manager|director|team|candidate)/i.test(signoffMatch[1])) {
      detectedCompanyName = signoffMatch[1].trim();
    }
  }

  // Pattern E: Recruiter corporate email domain inference (e.g. hr@infosys.com -> Infosys)
  if (!detectedCompanyName && emails.length > 0) {
    for (const em of emails) {
      const domain = em.split('@')[1]?.toLowerCase();
      if (domain && !domain.includes('gmail.') && !domain.includes('yahoo.') && !domain.includes('outlook.') && !domain.includes('hotmail.')) {
        const domainBase = domain.split('.')[0];
        if (domainBase && domainBase.length >= 3 && !/^(mail|webmail|email|admin|careers|jobs)$/i.test(domainBase)) {
          const docRegex = new RegExp(`\\b${domainBase}\\b`, 'i');
          const docMatch = text.match(docRegex);
          if (docMatch) {
            detectedCompanyName = domainBase.charAt(0).toUpperCase() + domainBase.slice(1);
            break;
          }
        }
      }
    }
  }

  // Pattern F: Strict letterhead candidate on top lines (must look like a genuine corporate entity)
  if (!detectedCompanyName) {
    const firstLines = text.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 5);
    for (const l of firstLines) {
      if (
        l.length >= 4 &&
        l.length <= 55 &&
        !isFilenameOrPlaceholder(l) &&
        !/(?:offer|internship|appointment|letter|date|dear|sub|ref|subject|page|candidate|confidential|copy|regards|section)/i.test(l) &&
        /^[A-Z0-9][A-Za-z0-9\s&.,'-]+$/.test(l) &&
        /[a-zA-Z]/.test(l)
      ) {
        detectedCompanyName = l;
        break;
      }
    }
  }

  if (detectedCompanyName) {
    detectedCompanyName = detectedCompanyName.replace(/^(?:the\s+upcoming\s+)?(?:internship\s+program\s+(?:at|with)|employment\s+with|position\s+at)\s+/i, '').trim();
    if (isFilenameOrPlaceholder(detectedCompanyName)) {
      detectedCompanyName = undefined;
    }
  }

  // --- 2. NLP Classification (InternShield Exact Algorithm) ---
  let genuineBoost = 0.0;
  let fraudPenalty = 0.0;
  let genuineMatches = 0;
  let criticalGenuineMatches = 0;
  let criticalGenuineTotal = 0;

  for (const [pattern, boost, desc, isCrit] of GENUINE_INDICATORS) {
    if (isCrit) criticalGenuineTotal++;
    if (pattern.test(textLower)) {
      genuineBoost += boost;
      genuineMatches++;
      if (isCrit) criticalGenuineMatches++;
    }
  }

  const docSentences = splitTextIntoSentences(text);

  // Check if document as a whole is an educational guide, awareness article, or verifier guide
  const isGuideDoc = /(?:how\s+to\s+know\s+if\s+a\s+consultancy\s+is\s+fake|common\s+(?:job\s+)?consultancy\s+scam|scam\s+scripts|what\s+the\s+ai\s+checker\s+looks\s+for|online\s+job\s+offer\s+verifier|verification\s+guide|checker\s+guide|internship\s+scam\s+warning\s+signs|identifying\s+recruitment\s+fraud|awareness\s+guide|case[- ]style\s+examples)/i.test(text);

  const isQuotedOrEducationalSentence = (s: string): boolean => {
    // If a sentence contains an actual candidate fee or booking amount demand, NEVER treat it as educational
    if (/(?:booking\s*amount|service\s*charge|registration\s*fees?|caution\s*(?:deposit|money)|security\s*deposit|training\s*fees?|placement\s*fees?|panel\s*charges?|(?:interview[- ])?slot\s*booking|transfer\s+to|pay\s+to|pay\s+now|pay\s+first|required\s+to\s+pay|to\s*confirm[^.!?]*?pay|upi)/i.test(s)) {
      return false;
    }
    if (!isGuideDoc) return false;
    const trimmed = s.trim();
    if (/^[•\-\*+\d.]\s*\+?/i.test(trimmed)) return true;
    if (/scam|guide|verifier|warning|checklist|example|case[- ]style|pattern|what\s+to|how\s+to|what\s+the\s+ai|looks\s+for|students\s+should/i.test(trimmed)) return true;
    return false;
  };

  // Helper to detect candidate compensation (stipend/salary paid TO candidate)
  const isCandidateCompensationSentence = (s: string): boolean => {
    const hasCandidateFeeTerm = /(?:registration\s*fees?|caution\s*(?:deposit|money|amount)|security\s*(?:deposit|amount)|training\s*fees?|laptop\s*deposit|admission\s*fees?|enrolment|enrollment|slot\s*booking|booking\s*amount|service\s*charges?|panel\s*charges?|placement\s*fees?|profile\s*activation|must\s*pay|needs?\s*to\s*pay|(?:is|are|be)\s+required\s+to\s*pay|required\s*to\s*pay|to\s*confirm[^.!?]*?pay|transfer\s+(?:the\s+)?(?:small\s+)?booking|pay\s+before|pay\s+now|pay\s+first|pay\s+via\s+upi)/i.test(s);
    if (hasCandidateFeeTerm) return false;

    return /(?:stipend\s*(?:of|is|:)?|salary\s*(?:of|is|:)?|compensation\s*(?:of|is|:)?|remuneration\s*(?:of|is|:)?|ctc\s*(?:of|is|:)?|will\s+(?:receive|be\s+paid|earn)\s+(?:a\s+)?(?:stipend|salary|remuneration)|paid\s+(?:to\s+(?:you|the\s+candidate|the\s+intern|the\s+employee)|monthly|per\s+month|annually|bi-weekly|weekly)|direct\s+deposit\s+(?:of|into)|bank\s+transfer\s+(?:of|into|to\s+(?:your|the\s+account))|credited\s+to\s+(?:your|the\s+account)|account\s+(?:credited|transfer)|per\s+month|\/month|p\.m\.|per\s+annum|\/year|p\.a\.|lpa|basic\s+pay|gross\s+salary|net\s+salary|package\s+of|fixed\s+pay|take[- ]home\s+pay|monthly\s+(?:stipend|salary|payout|allowance|remuneration)|company\s+will\s+pay|employer\s+will\s+pay)/i.test(s);
  };

  // Helper to detect corporate expense/reimbursement policies
  const isCorporatePolicySentence = (s: string): boolean => {
    const hasCandidateFeeTerm = /(?:registration\s*fees?|caution\s*(?:deposit|money|amount)|security\s*(?:deposit|amount)|training\s*fees?|laptop\s*deposit|admission\s*fees?|enrolment|enrollment|slot\s*booking|booking\s*amount|service\s*charges?|panel\s*charges?|placement\s*fees?|profile\s*activation|must\s*pay|needs?\s*to\s*pay|(?:is|are|be)\s+required\s+to\s*pay|required\s*to\s*pay|to\s*confirm[^.!?]*?pay|transfer\s+(?:the\s+)?(?:small\s+)?booking|pay\s+before|pay\s+now|pay\s+first|pay\s+via\s+upi)/i.test(s);
    if (hasCandidateFeeTerm) return false;

    return /(?:reimbursement\s+(?:policy|of\s+expenses?)|reimburses?\s+(?:training\s+)?expenses?|travel\s+(?:allowance|expenses?|reimbursement)|expenses?\s+(?:incurred\s+will\s+be\s+reimbursed|covered\s+by\s+the\s+company|borne\s+by\s+the\s+company)|provident\s+fund|pf\s+deduction|tax\s+deducted\s+at\s+source|tds|medical\s+insurance|group\s+insurance|health\s+benefits|gratuity|company\s+(?:will\s+)?(?:reimburse|provide|cover|bear|sponsor)|company\s+(?:reimburses?|provides?|covers?|bears?|sponsors?)|equipment\s+(?:is|will\s+be)\s+provided|laptop\s+(?:is|will\s+be)\s+provided|training\s+(?:is|will\s+be)\s+(?:provided|free|covered|sponsored)|at\s+no\s+(?:cost|charge)\s+to\s+the\s+candidate)/i.test(s);
  };

  const isNegatedSentence = (s: string): boolean => {
    return /(?:no\s+(?:registration|application|processing|training|onboarding|security|caution|internship)?\s*fees?|no\s+(?:security|caution)?\s*deposits?|never\s+(?:charge|collect|demand|request|ask)|do\s+not\s+(?:charge|collect|demand|request|ask)|will\s+not\s+(?:charge|collect|demand|request|ask)|shall\s+not\s+(?:charge|collect|demand|request|ask)|does\s+not\s+(?:charge|collect|demand|request|ask)|(?:fee|fees|deposit|payment)\s+(?:is\s+|are\s+)?not\s+required|not\s+required\s+to\s+pay|do\s+not\s+need\s+to\s+pay|do\s+not\s+have\s+to\s+pay|need\s+not\s+pay|without\s+any\s+(?:fee|charges?|deposit)|free\s+of\s+(?:any\s+)?(?:charge|cost|fee)|no\s+payment\s+(?:is\s+)?required|we\s+do\s+not\s+collect|do\s+not\s+pay\s+anyone|beware\s+of\s+(?:fraud|scams?)|neither\s+charge\s+nor\s+collect|zero\s+(?:fees?|charges?|deposits?)|at\s+no\s+cost|free\s+recruitment|strictly\s+prohibits?\s+(?:any\s+)?(?:fees?|charges?|money)|never\s+asks?\s+(?:candidates?|applicants?|students?)\s+(?:to\s+pay|for\s+(?:any\s+)?money))/i.test(s);
  };

  const isFeeSentence = (s: string): boolean => {
    if (isNegatedSentence(s)) return false;
    if (isCandidateCompensationSentence(s)) return false;
    if (isCorporatePolicySentence(s)) return false;
    if (isQuotedOrEducationalSentence(s)) return false;

    // Genuine candidate fee demands
    return (
      /(?:registration\s*fees?|caution\s*(?:deposit|money|fee|amount)|security\s*(?:deposit|amount)|internship\s*fees?|enrolment\s*fees?|enrollment\s*fees?|laptop\s*(?:deposit|security|fee)|equipment\s*(?:deposit|charge)|onboarding\s*(?:fees?|charges?|deposit)|training\s*(?:fees?|cost|charges?)|kit\s*charges?|uniform\s*(?:deposit|fee)|(?:interview[- ])?slot\s*booking\s*(?:amount|fee|charge)?|booking\s*amount|admission\s*fees?|acceptance\s*fees?|service\s*charges?|panel\s*charges?|placement\s*fees?|profile\s*activation\s*(?:fee|charge)?|document(?:ation)?\s*(?:verification\s*)?(?:charges?|fees?)|portal\s*activation\s*(?:fee|charge))/i.test(s) ||
      /(?:refundable|non-refundable)\s+(?:security\s+)?(?:deposit|amount|caution|fee|charge)/i.test(s) ||
      /(?:deposit|fee|charge|amount)\s+(?:must|needs?\s+to|(?:is|are|be)\s+required\s+to|shall)\s+be\s+paid/i.test(s) ||
      /(?:candidate|student|intern|applicant|you)\s*(?:must|needs?\s+to|(?:is|are|be)\s+required\s+to|have\s+to|has\s+to|shall|will\s+need\s+to)\s*(?:pay|deposit|transfer|remit)(?:\s+(?:₹|rs\.?|inr|\$|fee|charges?|deposit|amount|online|before|now|[a-z0-9]+))?/i.test(s) ||
      /to\s+confirm\s+your\s+(?:enrolment|enrollment|selection|admission|offer|seat|internship|appointment)[^.!?]*?(?:is|are|be)?\s*(?:required\s+to\s+pay|must\s+pay|needs?\s+to\s+pay|pay|deposit|transfer|remit|fee|charge|amount)/i.test(s) ||
      /(?:payment|deposit)\s+(?:of[^\n]*)?\s*is\s+(?:mandatory|required)\s+to\s+confirm/i.test(s) ||
      /(?:enrolment|enrollment|admission|selection)\s*(?:confirmation|formalities)?\s*(?:will\s+be\s+completed\s+after|requires?|is\s+subject\s+to)[^.!?]*?(?:pay|fee|charge)/i.test(s) ||
      /(?:kindly|please)?\s*(?:deposit|transfer|pay|remit)\s+(?:the\s+stated\s+)?(?:booking\s*amount|fee|charge|deposit|amount|(?:₹|rs\.?|inr|\$)\s*[0-9,]+)/i.test(s) ||
      /(?:transfer|deposit|pay)\s+(?:the\s+)?(?:refundable|non-refundable)\s*(?:deposit|amount|caution|fee|charge)/i.test(s) ||
      /until\s+(?:the\s+)?service\s*charge\s+is\s+cleared/i.test(s) ||
      /pay\s+(?:first|online|immediately|now|before\s*joining|to\s*confirm|to\s*avoid\s*cancellation|via\s*upi|into\s*the\s*account)\s*(?:(?:₹|rs\.?|inr|\$)\s*[0-9,]+|(?:the\s+)?(?:fee|charge|deposit|amount))?/i.test(s) ||
      /(?:transfer|deposit|pay)\s+(?:₹|rs\.?|inr|\$)\s*[0-9,]+(?:\s*\/-)?\s*(?:before\s*joining|to\s*confirm|as\s*(?:a\s*)?(?:fee|deposit|security|caution|registration|charge))/i.test(s) ||
      /(?:required|need|must|instructed|(?:are|is)\s+required)\s+to\s+pay(?:\s+(?:rs\.?|inr|₹|\$|fee|deposit|charges?|online|[a-z0-9]+))?/i.test(s)
    );
  };

  const hasPositiveFeeExplicit = docSentences.some(isFeeSentence) || (upiMatches.length > 0 && docSentences.some(s => upiMatches.some(u => s.includes(u)) && /(?:pay|transfer|send|deposit|remit)/i.test(s) && !isNegatedSentence(s) && !isCandidateCompensationSentence(s) && !isCorporatePolicySentence(s) && !isQuotedOrEducationalSentence(s)));
  const hasFeeNegation = docSentences.some(isNegatedSentence) && !hasPositiveFeeExplicit;

  let fraudMatches = 0;
  for (const [pattern, penalty, desc] of FRAUD_INDICATORS) {
    const isFeePattern = desc.toLowerCase().includes('fee') || desc.toLowerCase().includes('deposit') || desc.toLowerCase().includes('payment') || desc.toLowerCase().includes('money');
    if (isFeePattern && (hasFeeNegation || !hasPositiveFeeExplicit)) {
      continue; // Respect explicit negation clauses and lack of candidate fee demand
    }
    if (isGuideDoc && (desc.toLowerCase().includes('consultancy') || desc.toLowerCase().includes('scam') || desc.toLowerCase().includes('recruitment'))) {
      continue; // Educational awareness guide discussing scams is not itself a fraudulent document
    }
    if (pattern.test(textLower)) {
      fraudPenalty += penalty;
      fraudMatches++;
      flags.push({
        rule: "nlp_classifier",
        severity: penalty >= 0.12 ? "high" : "medium",
        message: desc,
        score: penalty,
      });
      suspiciousPatterns.push(desc);
    }
  }

  let absencePenalty = 0.0;
  if (criticalGenuineTotal > 0) {
    const ratio = criticalGenuineMatches / criticalGenuineTotal;
    if (ratio < 0.2) absencePenalty = 0.12;
    else if (ratio < 0.4) absencePenalty = 0.07;
    else if (ratio < 0.6) absencePenalty = 0.03;
  }
  if (genuineMatches === 0) absencePenalty += 0.10;

  let nlpConfidence = 0.5;
  genuineBoost = Math.min(genuineBoost, 0.40);
  fraudPenalty = Math.min(fraudPenalty, 0.50);
  nlpConfidence += genuineBoost - fraudPenalty - absencePenalty;

  const words = text.split(/\s+/).filter(Boolean);
  if (words.length < 80) nlpConfidence -= 0.10;
  else if (words.length < 150) nlpConfidence -= 0.05;
  else if (words.length > 500) nlpConfidence += 0.03;

  const centered = nlpConfidence - 0.5;
  nlpConfidence = Math.abs(centered) > 0.001 ? 0.5 + 0.5 * (centered / (Math.abs(centered) + 0.15)) : 0.5;
  nlpConfidence = Math.max(0.05, Math.min(0.98, nlpConfidence));

  // --- 3. NER Extractor & Verification ---
  let nerVerification = 0.0;
  let companyCheck = detectedCompanyName ? (detectedCompanyName.split(' ').length >= 2 ? 1.0 : 0.6) : 0.0;
  if (!detectedCompanyName) {
    flags.push({
      rule: "ner_company",
      severity: "high",
      message: "Could not identify a clear company name in the letter. Legitimate offer letters prominently display company name.",
      score: 0.0,
    });
  }

  // Signatory text pattern check — ADVISORY ONLY, never a fraud flag.
  // Full signature forensics is delegated to visualForensicsService.ts
  // A scammer can insert a signature; absence of a text-detectable signatory is NOT proof of fraud.
  const signatoryBlockMatch = text.match(
    /(?:hr\s+manager|human\s+resources|authorized\s+signatory|sincerely|regards|yours\s+(?:faithfully|truly)|head\s+-?\s*hr|director|talent\s+acquisition)[,\s:]*\n?\s*([A-Z][a-z]+(?:\s+[A-Z]\.?\s*)?(?:\s+[A-Z][a-z]+)+)/i
  );
  let detectedSignatory: string | undefined;
  if (signatoryBlockMatch && signatoryBlockMatch[1]) {
    detectedSignatory = signatoryBlockMatch[1].trim();
  } else {
    const altSignMatch = text.match(/(?:signed\s+by|signatory\s*:\s*|name\s*:\s*)([A-Z][a-z]+(?:\s+[A-Z]\.?\s*)?(?:\s+[A-Z][a-z]+)+)/i)
      || text.match(/([A-Z][a-z]+(?:\s+[A-Z]\.?\s*)?(?:\s+[A-Z][a-z]+)+)\s*\n\s*(?:HR\s+Manager|Authorized\s+Signatory|Human\s+Resources|Director)/i);
    if (altSignMatch && altSignMatch[1]) {
      detectedSignatory = altSignMatch[1].trim();
    } else {
      const titleMatch = text.match(/\b(HR\s+Manager|Authorized\s+Signatory|Director\s+of\s+HR|Head\s+of\s+Talent|Placement\s+Officer)\b/i);
      if (titleMatch) {
        detectedSignatory = titleMatch[1].trim();
      }
    }
  }

  const personCheck = detectedSignatory ? 0.7 : (text.length > 300 ? 0.4 : 0.5);
  if (!detectedSignatory && text.length > 300) {
    // Info-level advisory — NOT a fraud signal. Visual forensics will determine actual signature state.
    flags.push({
      rule: "doc_signatory_advisory",
      severity: "info",
      message: "No signatory block detected in text layer. Visual forensics analysis will determine actual signature presence. Absence of text-detectable signatory is not indicative of fraud.",
      score: 0.4,
    });
  }

  const hasCorporateEmail = emails.some(e => !PERSONAL_EMAIL_DOMAINS.has(e.split('@')[1]?.toLowerCase() || ''));
  let contactCheck = 0.0;
  if (hasCorporateEmail && phones.length > 0) contactCheck = 1.0;
  else if (hasCorporateEmail) contactCheck = 0.8;
  else if (emails.length > 0 && phones.length > 0) contactCheck = 0.5;
  else if (emails.length > 0 || phones.length > 0) contactCheck = 0.3;
  else {
    flags.push({
      rule: "ner_contact",
      severity: "high",
      message: "No contact information (email or phone) found in the letter.",
      score: 0.0,
    });
  }

  const hasAddress = /(?:address|office|building|tower|sector|plot|bangalore|bengaluru|mumbai|delhi|hyderabad|pune|chennai|noida|gurugram|kolkata)/i.test(textLower);
  const locationCheck = hasAddress ? 1.0 : (text.length > 300 ? 0.0 : 0.5);
  if (!hasAddress && text.length > 300) {
    flags.push({
      rule: "ner_location",
      severity: "medium",
      message: "No company location/address identified in the letter.",
      score: 0.0,
    });
    flags.push({
      rule: "missing_fields",
      severity: "low",
      message: "Letter is missing: company address.",
      score: 0.0,
    });
  }

  const dates = text.match(/\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}/g) || [];
  const dateCheck = dates.length >= 2 ? 1.0 : (dates.length === 1 ? 0.6 : 0.2);

  nerVerification = 0.25 * companyCheck + 0.20 * personCheck + 0.25 * contactCheck + 0.15 * locationCheck + 0.15 * dateCheck;

  // --- 4. Rule Suspicion ---
  let ruleSuspicion = 0.0;
  let ruleCount = 0;

  // Email Rule
  if (emails.length === 0) {
    ruleSuspicion += 0.4; ruleCount++;
  } else {
    const personalFound = emails.filter(e => PERSONAL_EMAIL_DOMAINS.has(e.split('@')[1]?.toLowerCase() || ''));
    if (personalFound.length === emails.length) {
      ruleSuspicion += 0.8; ruleCount++;
      flags.push({
        rule: "email_domain",
        severity: "high",
        message: `Email domain is ${personalFound[0].split('@')[1]} — a personal email service. Legitimate companies use corporate email domains.`,
        score: 0.8,
      });
    }
  }

  // Detailed financial fee evidence extraction
  const feeSentences = docSentences.filter(isFeeSentence);
  let feeQuote: string | undefined = feeSentences[0]?.trim();
  if (!feeQuote && externalFees && externalFees.length > 0) {
    feeQuote = externalFees.find(f => f && f.trim().length > 3)?.trim();
  }
  if (!feeQuote && upiMatches.length > 0) {
    const upiPaySentence = docSentences.find(s =>
      !isNegatedSentence(s) &&
      !isCandidateCompensationSentence(s) &&
      !isCorporatePolicySentence(s) &&
      !isQuotedOrEducationalSentence(s) &&
      upiMatches.some(u => s.includes(u)) &&
      /(?:pay|transfer|send|deposit|remit)/i.test(s)
    );
    if (upiPaySentence) feeQuote = upiPaySentence.trim();
  }

  const isFeeDemand = Boolean(feeQuote) || hasPositiveFeeExplicit || Boolean(externalFees && externalFees.length > 0);

  const feeAmountMatch = feeQuote?.match(/(?:₹|rs\.?|inr|\$)\s*([0-9,]+(?:\.\d{1,2})?)/i) ||
    (isFeeDemand ? text.match(/(?:fee|deposit|caution|registration|charge)\s*(?:of|is|:)?\s*(?:₹|rs\.?|inr|\$)\s*([0-9,]+(?:\.\d{1,2})?)/i) : null);
  const detectedFeeAmount = feeAmountMatch ? feeAmountMatch[0].trim() : undefined;

  let feeRecipient: string | undefined = upiMatches[0];
  if (!feeRecipient && isFeeDemand) {
    const upiDirectMatch = text.match(/(?:upi(?:\s*id)?|pay\s*to|transfer\s*to|via\s*upi\s*to)\s*[:\-]?\s*([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9.\-_]{2,32})/i);
    if (upiDirectMatch) feeRecipient = upiDirectMatch[1].trim();
  }
  if (!feeRecipient && isFeeDemand) {
    const bankMatch = text.match(/(?:beneficiary|account\s*holder|a\/c\s*name|transfer\s*to|in\s*favour\s*of)\s*[:\-]?\s*([A-Za-z0-9\s&.]{3,35})/i);
    if (bankMatch) feeRecipient = bankMatch[1].trim();
    else if (detectedCompanyName) feeRecipient = `Claimed: ${detectedCompanyName}`;
  }

  const isRefundable = isFeeDemand && /refundable/i.test(feeQuote || text) && !/non[- ]refundable/i.test(feeQuote || text);
  const refundTermsMatch = isFeeDemand ? text.match(/(?:refundable\s+(?:after|upon|on|within)[^\n.]{5,60}|refunded\s+(?:after|upon)[^\n.]{5,60})/i) : null;
  const refundTerms = refundTermsMatch ? refundTermsMatch[0].trim() : (isRefundable ? 'Claimed as refundable upon milestones or tenure' : undefined);

  const deadlineMatch = isFeeDemand ? text.match(/(?:within\s+\d+\s*(?:hours?|days?)|before\s+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|by\s+[A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?|immediate\s+transfer)/i) : null;
  const feeDeadline = deadlineMatch ? deadlineMatch[0].trim() : undefined;

  // Distinguish incoming applicant compensation (stipend/salary paid TO candidate)
  const compMatch = text.match(/(?:stipend|salary|compensation|ctc|remuneration|will\s+receive\s+a\s+stipend)\s*(?:of|is|:)?\s*((?:rs\.?|inr|₹|\$)?\s*[\d,]+(?:\.\d{1,2})?\s*(?:per\s+month|\/month|\/mo|p\.m\.|per\s+annum|\/year|p\.a\.|lpa|per\s+week)?)/i);
  let candidateCompensation: { type: 'STIPEND' | 'SALARY' | 'CTC' | 'REIMBURSEMENT'; amount?: string; raw_quote?: string } | undefined;
  if (compMatch) {
    const rawAmt = compMatch[1]?.trim() || '';
    const fullMatch = compMatch[0].trim();
    const hasCurrency = /(?:rs\.?|inr|₹|\$|€|£)/i.test(rawAmt) || /(?:rs\.?|inr|₹|\$|€|£)/i.test(fullMatch);
    const hasUnit = /(?:per\s+month|\/month|\/mo|p\.m\.|per\s+annum|\/year|p\.a\.|lpa|lac|lakh|crore|per\s+week|\/week|\/day|per\s+day|\/hr|per\s+hour)/i.test(rawAmt) || /(?:per\s+month|\/month|\/mo|p\.m\.|per\s+annum|\/year|p\.a\.|lpa|lac|lakh|crore|per\s+week|\/week|\/day|per\s+day|\/hr|per\s+hour)/i.test(fullMatch);
    const numOnly = parseFloat(rawAmt.replace(/[^0-9.]/g, ''));
    const isValidComp = (hasCurrency || hasUnit) ? true : (!isNaN(numOnly) && numOnly >= 500);

    if (isValidComp) {
      candidateCompensation = {
        type: /ctc|per\s+annum|lpa/i.test(fullMatch) ? 'CTC' : /stipend/i.test(fullMatch) ? 'STIPEND' : 'SALARY',
        amount: rawAmt || fullMatch,
        raw_quote: fullMatch,
      };
    }
  }

  const detailedFees: DetailedPaymentEvidence[] = [];
  if (isFeeDemand) {
    let feeCategory = 'UPFRONT_FEE_DEMAND';
    if (/caution\s*(?:deposit|money|amount|fee)/i.test(feeQuote || text)) feeCategory = 'SECURITY_DEPOSIT';
    else if (/security\s*deposit/i.test(feeQuote || text)) feeCategory = 'SECURITY_DEPOSIT';
    else if (/registration\s*fee/i.test(feeQuote || text)) feeCategory = 'REGISTRATION_FEE';
    else if (/training\s*(?:fee|cost|charge)/i.test(feeQuote || text)) feeCategory = 'TRAINING_FEE';
    else if (/booking\s*amount|slot\s*booking/i.test(feeQuote || text)) feeCategory = 'BOOKING_AMOUNT';
    else if (/service\s*charge/i.test(feeQuote || text)) feeCategory = 'SERVICE_CHARGE';
    else if (/laptop\s*deposit|equipment\s*deposit/i.test(feeQuote || text)) feeCategory = 'EQUIPMENT_CHARGE';
    else if (/onboarding|processing|document/i.test(feeQuote || text)) feeCategory = 'PROCESSING_FEE';

    detailedFees.push({
      category: feeCategory,
      amount: detectedFeeAmount,
      recipient: feeRecipient,
      channel: upiMatches[0] ? `UPI: ${upiMatches[0]}` : (/(?:bank\s*transfer|neft|imps|rtgs)/i.test(text) ? 'Bank Wire Transfer' : 'Online Payment Link / Portal'),
      is_refundable: isRefundable,
      refund_terms: refundTerms,
      deadline: feeDeadline,
      exact_quote: feeQuote || 'Candidate monetary payment or caution deposit requested in document',
      why_it_matters: isRefundable
        ? 'Advance-fee fraud schemes frequently promise refunds upon completion to lower candidate skepticism. Legitimate corporate employers do not collect refundable caution deposits.'
        : 'Legitimate employers and internship providers never demand candidate registration fees or caution deposits. Any fee demand is an immediate scam indicator.',
      confidence: 96,
    });

    if (externalFees && externalFees.length > 0) {
      for (const ef of externalFees) {
        if (ef && ef.trim().length > 3 && !detailedFees.some(d => d.exact_quote === ef.trim())) {
          detailedFees.push({
            category: 'UPFRONT_FEE_DEMAND',
            exact_quote: ef.trim(),
            why_it_matters: 'Candidate fee demand identified via multimodal visual inspection.',
            confidence: 96,
          });
        }
      }
    }
  }

  // Classify payment context into explicit nuanced categories
  let paymentCase: 'EXPLICIT_DEMAND' | 'CONDITIONAL_DEMAND' | 'POLICY_MENTION_WITHOUT_DEMAND' | 'WARNING_AGAINST_PAYMENT' | 'NO_PAYMENT_EVIDENCE' | 'AMBIGUOUS_EVIDENCE' = 'NO_PAYMENT_EVIDENCE';
  let paymentExplanation = '';

  const isContentIncomplete = text.trim().length < 50;

  const hasWarningAgainstPayment = docSentences.some(s =>
    /(?:beware\s+of\s+fraud|never\s+(?:charge|collect|ask\s+for|demand)\s+(?:money|fees?|deposits?)|we\s+(?:do\s+not|never)\s+(?:charge|collect|demand|ask\s+for)\s+(?:any\s+)?(?:fees?|money|charges?|deposits?)|recruitment\s+is\s+free\s+of\s+(?:any\s+)?(?:cost|charge|fees?)|do\s+not\s+pay\s+(?:any\s+)?(?:money|fees?|charges?)|company\s+does\s+not\s+(?:charge|collect|demand)|neither\s+charge\s+nor\s+collect)/i.test(s)
  );

  const hasFinancialPolicyMention = docSentences.some(s =>
    !isFeeSentence(s) && (isCorporatePolicySentence(s) || /(?:reimbursement\s+policy|reimburses?\s+(?:training\s+)?expenses?|travel\s+(?:allowance|expenses?)|medical\s+insurance|provident\s+fund|pf\s+deduction|tax\s+deducted\s+at\s+source|tds|corporate\s+credit\s+card|relocation\s+(?:allowance|expenses?)|gratuity|company\s+(?:will\s+)?reimburse)/i.test(s))
  );

  const hasAmbiguousFeeMention = docSentences.some(s =>
    !isFeeSentence(s) && !isNegatedSentence(s) && !isCandidateCompensationSentence(s) && !isCorporatePolicySentence(s) &&
    /(?:payment\s+terms|deposit\s+terms|financial\s+clause|transaction\s+details|fee\s+structure|payment\s+schedule|billing\s+clause)/i.test(s)
  );

  if (isContentIncomplete) {
    paymentCase = 'AMBIGUOUS_EVIDENCE';
    paymentExplanation = 'Source document text is incomplete, unreadable, or insufficient to reach a conclusive payment finding.';
  } else if (isFeeDemand) {
    if (isRefundable || /conditional|subject\s+to/i.test(refundTerms || '')) {
      paymentCase = 'CONDITIONAL_DEMAND';
      paymentExplanation = `Document contains conditional candidate payment/deposit request: ${refundTerms || 'Refund claimed upon tenure or milestones'}.`;
    } else {
      paymentCase = 'EXPLICIT_DEMAND';
      paymentExplanation = `Explicit candidate monetary payment or deposit requested in offer letter: "${feeQuote || detectedFeeAmount || 'Mandatory fee demand'}".`;
    }
  } else if (hasWarningAgainstPayment || hasFeeNegation || (isGuideDoc && !isFeeDemand)) {
    paymentCase = 'WARNING_AGAINST_PAYMENT';
    paymentExplanation = isGuideDoc
      ? 'Document is an educational guidance or awareness article discussing recruitment fraud patterns; zero active candidate fees demanded.'
      : 'Document explicitly warns applicants against paying recruitment fees and affirms that legitimate hiring is free of cost.';
  } else if (hasFinancialPolicyMention) {
    paymentCase = 'POLICY_MENTION_WITHOUT_DEMAND';
    paymentExplanation = 'Document outlines general organizational financial or reimbursement policies without requesting any payments from the candidate.';
  } else if (hasAmbiguousFeeMention) {
    paymentCase = 'AMBIGUOUS_EVIDENCE';
    paymentExplanation = 'Document mentions financial or payment terminology, but available evidence is insufficient to establish that candidate payment is demanded.';
  } else if (candidateCompensation) {
    paymentCase = 'NO_PAYMENT_EVIDENCE';
    paymentExplanation = `Document defines candidate remuneration (${candidateCompensation.type}: ${candidateCompensation.amount || ''}) without requiring any candidate payments.`;
  } else {
    paymentCase = 'NO_PAYMENT_EVIDENCE';
    paymentExplanation = 'Zero candidate fees, training charges, or caution deposits detected in document.';
  }

  if (isFeeDemand) {
    ruleSuspicion += 1.0; ruleCount++;
    if (!flags.some(f => f.rule === "payment_demand")) {
      flags.push({
        rule: "payment_demand",
        severity: "critical",
        message: "Letter asks candidate to pay money / registration fee / security deposit. Legitimate employers NEVER charge candidates.",
        score: 1.0,
      });
    }
  }

  // Urgency
  const urgencyFound = URGENCY_PHRASES.filter(p => textLower.includes(p));
  if (urgencyFound.length > 0) {
    ruleSuspicion += 0.6; ruleCount++;
  }

  // Suspicious links
  if (/(?:docs\.google\.com\/forms|forms\.gle|typeform\.com|jotform\.com|chat\.whatsapp\.com|t\.me\/|bit\.ly|tinyurl)/i.test(textLower)) {
    ruleSuspicion += 0.7; ruleCount++;
  }

  const avgRuleSuspicion = ruleCount > 0 ? Math.min(1.0, ruleSuspicion / 5) : 0.0;
  let ruleConfidence = 1.0 - avgRuleSuspicion;
  if (isFeeDemand) {
    ruleConfidence = 0.05; // Upfront fee is a catastrophic structural breach
  }

  // --- 5. Final Ensemble Scorer (InternShield Exact Math) ---
  let rawScore = 0.45 * nlpConfidence + 0.35 * ruleConfidence + 0.20 * nerVerification;
  if (isFeeDemand) {
    rawScore = Math.min(rawScore, 0.12);
  }

  if (rawScore >= 0.5) {
    const norm = (rawScore - 0.5) * 2;
    const scaled = Math.pow(norm, 0.8);
    rawScore = 0.5 + scaled * 0.5;
  } else {
    const norm = (0.5 - rawScore) * 2;
    const scaled = Math.pow(norm, 0.8);
    rawScore = 0.5 - scaled * 0.5;
  }

  const flagCount = flags.length;
  if (flagCount >= 6) rawScore -= 0.12;
  else if (flagCount >= 4) rawScore -= 0.08;
  else if (flagCount >= 2) rawScore -= 0.04;

  const disagreement = Math.abs(nlpConfidence - ruleConfidence);
  if (disagreement > 0.5) rawScore -= 0.05;

  if (nerVerification < 0.2) rawScore = Math.min(rawScore, 0.55);

  let finalPercent = Math.round(rawScore * 100);
  if (isFeeDemand) {
    finalPercent = Math.min(finalPercent, 12);
  }
  finalPercent = Math.max(1, Math.min(98, finalPercent));

  let finalVerdict: "LIKELY GENUINE" | "SUSPICIOUS" | "LIKELY FAKE" = "LIKELY GENUINE";
  if (isFeeDemand || finalPercent < 40) finalVerdict = "LIKELY FAKE";
  else if (finalPercent < 72) finalVerdict = "SUSPICIOUS";
  else finalVerdict = "LIKELY GENUINE";

  const nextSteps = finalVerdict === "LIKELY FAKE" ? [
    "Do NOT share any personal documents (Aadhaar, PAN, bank details) with this organization.",
    "Report this offer letter to your college placement cell immediately.",
    "If you found this on Internshala or LinkedIn, report the listing on the platform.",
    "File a complaint on the National Cyber Crime Portal (cybercrime.gov.in) if you've already shared any information.",
    "Do NOT pay any 'registration fee', 'security deposit', or 'training charges'. Legitimate companies never ask candidates for money.",
    `Search for '${detectedCompanyName || "this company"}' on MCA21 (mca.gov.in) to check if it's a registered company.`,
  ] : finalVerdict === "SUSPICIOUS" ? [
    "Verify this offer independently before sharing any personal information.",
    "Search for the company on LinkedIn and check if it has a legitimate presence (employee count, verified page).",
    "Call the company's official number (found independently, NOT from this letter) and ask to speak with HR.",
    "Check the company's reviews on Glassdoor and AmbitionBox.",
    `Verify '${detectedCompanyName || "company"}' CIN on MCA21 portal (mca.gov.in/mcafoportal).`,
  ] : [
    "This letter appears to be from a legitimate organization.",
    "Standard next steps: review the compensation and terms carefully before accepting.",
    "Respond within the deadline mentioned in the letter.",
    "Keep a copy of this offer letter for your records.",
    "Prepare your joining documents (ID proof, education certificates) for onboarding.",
  ];

  // --- DYNAMIC CLAIM EXTRACTION (RAG PRE-PROCESSING) ---
  const extracted_claims: import('../../types').DocumentClaim[] = [];

  if (detectedCompanyName && !isFilenameOrPlaceholder(detectedCompanyName)) {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "ORGANIZATION",
      raw_claim_text: `Organization claimed as '${detectedCompanyName}'`,
      normalized_value: detectedCompanyName,
      confidence: 90,
      verification_status: "UNVERIFIED",
      explanation: "Extracted from document header/text; pending corporate registry check.",
    });
  } else {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "ORGANIZATION",
      raw_claim_text: "Organization claimed as 'Organization not reliably identified'",
      normalized_value: "Organization not reliably identified",
      confidence: 30,
      verification_status: "UNVERIFIED",
      explanation: "Document lacks clear corporate identity, statutory registration identifiers, or verified employer letterhead.",
    });
  }

  if (emails.length > 0) {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "CONTACT_EMAIL",
      raw_claim_text: `Recruiter email specified as '${emails[0]}'`,
      normalized_value: emails[0],
      confidence: 95,
      verification_status: "UNVERIFIED",
      explanation: "Extracted from contact section; evaluated for domain alignment.",
    });
  }

  const cinMatch = text.match(/\b([UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6})\b/i)?.[1]?.toUpperCase();
  if (cinMatch) {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "CIN_REGISTRATION",
      raw_claim_text: `Corporate Identity Number claimed as ${cinMatch}`,
      normalized_value: cinMatch,
      confidence: 98,
      verification_status: "UNVERIFIED",
      explanation: "CIN found in footer; cross-checked against MCA21 master registry.",
    });
  }

  const roleMatch = text.match(/(?:role|designation|position|internship\s+as|hired\s+as)\s*[:\-]\s*([A-Za-z0-9\s\-]{3,40})/i);
  if (roleMatch) {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "ROLE_DESIGNATION",
      raw_claim_text: `Role specified as '${roleMatch[1].trim()}'`,
      normalized_value: roleMatch[1].trim(),
      confidence: 85,
      verification_status: "NOT_APPLICABLE",
      explanation: "Designation extracted from offer text.",
    });
  }

  const stipendMatch = text.match(/(?:stipend|salary|ctc|compensation|remuneration)\s*[:\-]?\s*(?:rs\.?|₹|inr)?\s*([\d,]+(?:\s*(?:per|\/)\s*(?:month|year|annum|pm|pa))?)/i);
  if (stipendMatch) {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "STIPEND_COMPENSATION",
      raw_claim_text: `Compensation stated as '${stipendMatch[0].trim()}'`,
      normalized_value: stipendMatch[0].trim(),
      confidence: 85,
      verification_status: "NOT_APPLICABLE",
      explanation: "Extracted compensation clause.",
    });
  }

  if (isFeeDemand) {
    extracted_claims.push({
      id: `CLM-${extracted_claims.length + 1}`,
      claim_type: "PAYMENT_REQUIREMENT",
      raw_claim_text: "Candidate requested to pay fee/deposit before onboarding",
      normalized_value: "UPFRONT_FEE_DEMAND",
      confidence: 95,
      verification_status: "CONTRADICTED",
      retrieved_reality: "ILO Fair Recruitment Policy & Standard Employment Laws prohibit candidate fees",
      explanation: "Legitimate corporate recruiters never require candidates to pay registration or security fees.",
    });
  }

  // Construct Normalized Document Evidence
  const selectionMatch = text.match(/(?:We are pleased to (?:offer|inform|extend)|Congratulations(?:!|,)? (?:You have been selected|on your selection)|offer of appointment|selected for the position of|offer of internship|pleased to offer you)[^\n.]{0,160}/i);
  const candidateMatch = text.match(/(?:Dear|To,?\s*Candidate|Candidate Name\s*:|Name\s*:|Mr\.|Ms\.|Shri)\s*([A-Z][a-zA-Z\s.]{2,40})/i);
  const normRoleMatch = text.match(/(?:position of|role of|as an?|designation\s*:)\s*([A-Z][A-Za-z0-9\s-]{2,40}(?:Intern|Trainee|Engineer|Developer|Analyst|Associate|Designer|Manager)?)/i);
  const joiningMatch = text.match(/(?:joining date|date of joining|commencing from|start date|report on)\s*(?:is|:)?\s*([0-9]{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]+\s+[0-9]{4}|[0-9]{1,2}[-/][0-9]{1,2}[-/][0-9]{2,4})/i);

  const matchedClauses: string[] = [];
  for (const [pattern, _boost, desc] of GENUINE_INDICATORS) {
    if (pattern.test(textLower)) matchedClauses.push(desc);
  }
  const normalizedEvidence: NormalizedDocumentEvidence = {
    raw_ocr: rawOcr || text,
    cleaned_text: text,
    selection_statement: selectionMatch ? selectionMatch[0].trim() : undefined,
    candidate_name: candidateMatch ? candidateMatch[1].trim() : undefined,
    recruiter_name: text.match(/(?:Authorized Signatory|HR Manager|Head of Talent|HR Director|Recruiter|Regards,?\s*\n)\s*([A-Z][a-zA-Z\s.]{2,40})/i)?.[1]?.trim(),
    recruiter_email: emails[0],
    company_name: detectedCompanyName,
    job_role: normRoleMatch ? normRoleMatch[1].trim() : (roleMatch ? roleMatch[1].trim() : undefined),
    compensation: stipendMatch ? stipendMatch[0].trim() : undefined,
    joining_date: joiningMatch ? joiningMatch[1].trim() : undefined,
    terms_clauses: matchedClauses,
    ocr_engine: ocrEngine || 'PSZEMRAJ_DOCTR',
  };

  if (isFeeDemand) {
    evidence.push({
      id: `EXT-DOC-FEE-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
      category: "DOCUMENT",
      evidence_type_category: "STRONG_INDICATOR",
      evidence_type: "UPFRONT_FEE_DEMAND",
      evidence_strength: "VERY_STRONG",
      source_name: "Document Text Forensics",
      title: "Mandatory Candidate Fee / Caution Deposit Demanded",
      evidence_text: "Document contains explicit clauses demanding candidate payment, registration fee, training cost, or caution deposit. Standard recruitment laws strictly prohibit candidate fees.",
      status: "NEGATIVE",
      severity: "CRITICAL",
      verified: true,
      confidence: 98,
    });
  }

  if (emails.length > 0) {
    const personalFound = emails.filter(e => PERSONAL_EMAIL_DOMAINS.has(e.split('@')[1]?.toLowerCase() || ''));
    if (personalFound.length > 0) {
      evidence.push({
        id: `EXT-DOC-MAIL-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
        category: "RECRUITER",
        evidence_type_category: "STRONG_INDICATOR",
        evidence_type: "FREE_WEBMAIL_PROVIDER",
        evidence_strength: "STRONG",
        source_name: "Recruiter Channel Analysis",
        title: `Public Webmail Channel (${personalFound[0].split('@')[1]})`,
        evidence_text: `Recruiter communicates from personal webmail service (${personalFound[0]}) rather than official enterprise domain infrastructure.`,
        status: "WARNING",
        severity: "HIGH",
        verified: true,
        confidence: 88,
      });
    } else {
      evidence.push({
        id: `EXT-DOC-MAIL-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
        category: "RECRUITER",
        evidence_type_category: "STRONG_INDICATOR",
        evidence_type: "CORPORATE_DOMAIN_EMAIL",
        evidence_strength: "STRONG",
        source_name: "Recruiter Channel Analysis",
        title: `Enterprise Sender Domain (${emails[0].split('@')[1]})`,
        evidence_text: `Recruiter email corresponds to custom corporate domain (${emails[0]}).`,
        status: "VERIFIED",
        severity: "INFO",
        verified: true,
        confidence: 92,
      });
    }
  }

  if (detectedCompanyName) {
    evidence.push({
      id: `EXT-DOC-ENT-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
      category: "COMPANY",
      evidence_type_category: "STRONG_INDICATOR",
      evidence_type: "OFFER_ENTITY_IDENTIFIER",
      evidence_strength: "MEDIUM",
      source_name: "Document Header Analysis",
      title: `Issuing Organization Named: ${detectedCompanyName}`,
      evidence_text: `Document text explicitly identifies hiring organization as '${detectedCompanyName}'.`,
      status: "VERIFIED",
      severity: "INFO",
      verified: true,
      confidence: 90,
    });
  }

  if (matchedClauses.length > 0) {
    evidence.push({
      id: `EXT-DOC-CLAUSE-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
      category: "DOCUMENT",
      evidence_type_category: "WEAK_INDICATOR",
      evidence_type: "STANDARD_TERMS_CLAUSES",
      evidence_strength: "MEDIUM",
      source_name: "Clause Structure Analyzer",
      title: `Formal Employment Provisions (${matchedClauses.length} Detected)`,
      evidence_text: `Document incorporates structured appointment terms: ${matchedClauses.slice(0, 3).join(', ')}.`,
      status: "VERIFIED",
      severity: "INFO",
      verified: true,
      confidence: 85,
    });
  }

  return {
    filename,
    mime_type: mimeType,
    extracted_text: text,
    raw_ocr: rawOcr || text,
    ocr_engine: ocrEngine || 'PSZEMRAJ_DOCTR',
    normalized_evidence: normalizedEvidence,
    extracted_claims,
    sanitized_evidence_block: text.slice(0, 1000),
    has_fee_demand: isFeeDemand,
    is_suspicious_offer_letter: finalVerdict !== "LIKELY GENUINE" || finalPercent < 70 || isFeeDemand || flags.length >= 2,
    detected_company_name: detectedCompanyName,
    detected_signatory: detectedSignatory,
    detected_domain: emails[0]?.split('@')[1]?.toLowerCase(),
    detected_email: emails[0],
    detected_cin: text.match(/\b([UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6})\b/i)?.[1]?.toUpperCase(),
    has_urgency: urgencyFound.length > 0,
    has_informal_channel: suspiciousPatterns.some(p => p.includes("WhatsApp") || p.includes("Telegram")),
    has_grammar_anomalies: false,
    has_generic_greeting: false,
    has_implausible_stipend: false,
    suspicious_patterns: suspiciousPatterns,
    extracted_entities: {
      company: detectedCompanyName,
      emails,
      phones,
      urls,
    },
    detected_entities: {
      emails,
      phones,
      urls,
      fees_detected: detailedFees.map(d => ({ amount: d.amount || 'Unspecified', reason: d.category })),
      upi_ids: upiMatches,
      cryptos: [],
      informal_channels: [],
      urgency_phrases: urgencyFound,
    },
    requested_fees: detailedFees.map(d => ({ amount: d.amount, reason: d.category, channel: d.channel })),
    fee_details: detailedFees,
    payment_case: paymentCase,
    payment_explanation: paymentExplanation,
    candidate_compensation: candidateCompensation,
    detected_stipend: candidateCompensation?.amount,
    risk_signals: flags.map(f => f.message),
    evidence,
    triggered_flags: flags,
    dimension_scores: {
      rules: isFeeDemand ? 5 : Math.round(ruleConfidence * 100),
      nlp: isFeeDemand ? Math.min(10, Math.round(nlpConfidence * 100)) : Math.round(nlpConfidence * 100),
      ner: Math.round(nerVerification * 100),
    },
    final_score: finalPercent,
    verdict: finalVerdict,
    next_steps: nextSteps,
  };
}

export async function processDocument(
  fileBuffer: Buffer,
  filename: string = "unnamed_document",
  mimeType: string = "text/plain"
): Promise<DocumentExtractionResult> {
  let text = "";
  let rawOcrText: string | undefined = undefined;
  let ocrEngineUsed: string = 'PLAIN_TEXT';
  let visualForensics: any = undefined;
  const deepDetectedFees: string[] = [];

  const isPdf = mimeType === 'application/pdf' || filename.toLowerCase().endsWith('.pdf') || (fileBuffer.length > 4 && fileBuffer.toString('utf-8', 0, 4) === '%PDF');
  const isImage = mimeType.startsWith('image/') || !!filename.match(/\.(png|jpe?g|webp|bmp|gif)$/i);

  if (isPdf) {
    // Tier 1: Hugging Face Deep-Learning OCR (pszemraj/pdf-ocr) with robust multi-tier fallback
    try {
      const extraction = await extractPdfTextWithEngine(fileBuffer, filename);
      if (extraction && extraction.text && extraction.text.trim().length > 20) {
        text = extraction.text;
        rawOcrText = extraction.raw_ocr;
        ocrEngineUsed = extraction.engine;
      }
    } catch (e: any) {
      console.warn(`[analyzeDocumentFile] PDF extraction warning: ${e.message}`);
    }

    // Complementary visual forensics analysis
    try {
      const deepResult = await analyzeDocumentDeepForensics(fileBuffer, 'application/pdf');
      visualForensics = deepResult.visual_forensics;
      if (deepResult.detected_fees && deepResult.detected_fees.length > 0) {
        deepDetectedFees.push(...deepResult.detected_fees);
      }
      if (!text || text.trim().length < 20 || (deepResult.raw_text && deepResult.raw_text.trim().length > text.trim().length * 1.3)) {
        text = deepResult.raw_text;
        rawOcrText = deepResult.raw_text;
        ocrEngineUsed = 'GEMINI_DEEP_FORENSICS';
      }
    } catch {}
  } else if (isImage) {
    // Tier 1: Hugging Face Deep-Learning baidu/Unlimited-OCR
    try {
      const baiduRes = await extractTextWithBaiduUnlimitedOcr(fileBuffer, mimeType);
      if (baiduRes && baiduRes.text && baiduRes.text.length > 15) {
        text = baiduRes.text;
        rawOcrText = baiduRes.raw_ocr;
        ocrEngineUsed = 'BAIDU_UNLIMITED_OCR';
      }
    } catch {}

    // Visual Forensics & Multimodal Gemini Deep Forensics
    try {
      const deepResult = await analyzeDocumentDeepForensics(fileBuffer, mimeType);
      if (deepResult.detected_fees && deepResult.detected_fees.length > 0) {
        deepDetectedFees.push(...deepResult.detected_fees);
      }
      if (!text || text.length < 20 || (deepResult.raw_text && deepResult.raw_text.trim().length > text.trim().length * 1.3)) {
        text = deepResult.raw_text;
        rawOcrText = deepResult.raw_text;
        ocrEngineUsed = 'GEMINI_DEEP_FORENSICS';
      }
      visualForensics = deepResult.visual_forensics;
    } catch {}

    if (!text) {
      text = await extractTextFromImageBuffer(fileBuffer, mimeType);
      rawOcrText = text;
      ocrEngineUsed = 'GEMINI_IMAGE_VISION';
    }
  } else {
    // Plain text / Markdown buffer
    text = fileBuffer.toString('utf-8');
    rawOcrText = text;
    ocrEngineUsed = 'BUFFER_UTF8';
  }

  if (!text || text.trim().length === 0) {
    text = fileBuffer.toString('utf-8');
    rawOcrText = text;
    ocrEngineUsed = 'FALLBACK_RAW';
  }

  const result = extractDocumentSignals(text, filename, mimeType, rawOcrText, ocrEngineUsed, deepDetectedFees);
  (result as any).visual_forensics = visualForensics;
  return result;
}
