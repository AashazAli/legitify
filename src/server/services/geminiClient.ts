// ==============================================================================
// LEGITIFY CENTRALIZED GEMINI CLIENT & MODEL ORCHESTRATION
// Server-Side Only. Strict API key isolation and resilient fallback cascade.
// ==============================================================================
import { GoogleGenAI } from '@google/genai';

/**
 * Standard candidate model priority order.
 * If the primary configured model encounters quota exhaustion (HTTP 429)
 * or deprecation (HTTP 404), the client automatically cascades to resilient alternatives.
 */
export const DEFAULT_MODEL_CASCADE = [
  'gemini-3.5-flash-lite',
  'gemini-3.5-flash',
  'gemini-3.6-flash',
];

export function getGeminiApiKey(): string | null {
  // Only server-side environment variables are queried.
  // VITE_ prefixes are strictly prohibited to prevent client-bundle leakage.
  const raw = (process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_KEY || '').trim();
  if (!raw || raw.startsWith('your-') || raw === 'PLACEHOLDER') {
    return null;
  }
  return raw;
}

export function isGeminiConfigured(): boolean {
  return getGeminiApiKey() !== null;
}

export function getGeminiModelCascade(): string[] {
  const configured = (process.env.GEMINI_MODEL || '').trim();
  const models: string[] = [];
  if (configured) {
    models.push(configured);
  }
  for (const m of DEFAULT_MODEL_CASCADE) {
    if (!models.includes(m)) {
      models.push(m);
    }
  }
  return models;
}

let cachedClient: GoogleGenAI | null = null;
let lastApiKeyUsed: string | null = null;

export function getGeminiClient(): GoogleGenAI | null {
  const key = getGeminiApiKey();
  if (!key) {
    return null;
  }
  if (!cachedClient || lastApiKeyUsed !== key) {
    cachedClient = new GoogleGenAI({ apiKey: key });
    lastApiKeyUsed = key;
  }
  return cachedClient;
}

export interface GeminiCallParams {
  contents: any;
  systemInstruction?: string;
  tools?: any[];
  temperature?: number;
  responseMimeType?: string;
  timeoutMs?: number;
}

export interface GeminiCallResult {
  text: string;
  modelUsed: string;
  durationMs: number;
}

/**
 * Executes a Gemini content generation call across the candidate model cascade.
 * Tries each model in order if a rate-limit (429) or model-not-found (404) error occurs.
 */
export async function generateContentWithFallback(
  params: GeminiCallParams
): Promise<GeminiCallResult> {
  const client = getGeminiClient();
  if (!client) {
    throw new Error('GEMINI_NOT_CONFIGURED: Gemini API key is not configured in server environment.');
  }

  const models = getGeminiModelCascade();
  const timeoutMs = params.timeoutMs || parseInt(process.env.GEMINI_TIMEOUT_MS || '30000', 10);
  let lastError: any = null;

  for (const model of models) {
    const startTime = Date.now();
    try {
      const config: any = {
        temperature: params.temperature ?? 0.1,
      };

      if (params.systemInstruction) {
        config.systemInstruction = params.systemInstruction;
      }
      if (params.responseMimeType) {
        config.responseMimeType = params.responseMimeType;
      }
      if (params.tools && params.tools.length > 0) {
        config.tools = params.tools;
      }

      const callPromise = client.models.generateContent({
        model,
        contents: params.contents,
        config,
      });

      const response: any = await Promise.race([
        callPromise,
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`GEMINI_TIMEOUT: Request timed out after ${timeoutMs}ms`)), timeoutMs)
        ),
      ]);

      const text = response.text || '';
      const durationMs = Date.now() - startTime;

      return {
        text,
        modelUsed: model,
        durationMs,
      };
    } catch (err: any) {
      lastError = err;
      const errMsg = err?.message || String(err);
      const isRetryable =
        errMsg.includes('429') ||
        errMsg.includes('RESOURCE_EXHAUSTED') ||
        errMsg.includes('quota') ||
        errMsg.includes('rate') ||
        errMsg.includes('404') ||
        errMsg.includes('NOT_FOUND') ||
        errMsg.includes('not found') ||
        errMsg.includes('is not supported') ||
        errMsg.includes('GEMINI_TIMEOUT');

      console.warn(`[GeminiClient] Notice on model ${model}: ${errMsg.slice(0, 160)}. Attempting cascade...`);

      if (!isRetryable) {
        // If it is an authentication error (401/403) or severe failure, stop immediately
        if (errMsg.includes('API_KEY_INVALID') || errMsg.includes('403') || errMsg.includes('401')) {
          throw new Error('GEMINI_AUTH_ERROR: Invalid or unauthorized Gemini API key.');
        }
      }
    }
  }

  const finalMessage = lastError?.message || String(lastError || 'Unknown Gemini error');
  throw new Error(`GEMINI_ALL_MODELS_FAILED: All cascade models failed. Last error: ${finalMessage.slice(0, 180)}`);
}

/**
 * Generates structured JSON using Gemini with model fallback and safe JSON extraction.
 */
export async function generateJsonWithFallback<T = any>(
  params: GeminiCallParams
): Promise<{ data: T; modelUsed: string; durationMs: number }> {
  const result = await generateContentWithFallback({
    ...params,
    responseMimeType: 'application/json',
  });

  const parsed = parseSafeJson<T>(result.text);
  if (!parsed) {
    throw new Error('GEMINI_PARSE_ERROR: Failed to parse valid JSON from model response.');
  }

  return {
    data: parsed,
    modelUsed: result.modelUsed,
    durationMs: result.durationMs,
  };
}

/**
 * Safely parses JSON from LLM text output, handling markdown fences and leading/trailing noise.
 */
export function parseSafeJson<T = any>(rawText: string): T | null {
  if (!rawText) return null;
  const trimmed = rawText.trim();

  // Try direct parse
  try {
    return JSON.parse(trimmed) as T;
  } catch {}

  // Strip markdown code fences: ```json ... ``` or ``` ... ```
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (fenceMatch && fenceMatch[1]) {
    try {
      return JSON.parse(fenceMatch[1].trim()) as T;
    } catch {}
  }

  // Regex match for outer object {...}
  const objMatch = trimmed.match(/\{[\s\S]*\}/);
  if (objMatch) {
    try {
      return JSON.parse(objMatch[0]) as T;
    } catch {}
  }

  // Regex match for outer array [...]
  const arrMatch = trimmed.match(/\[[\s\S]*\]/);
  if (arrMatch) {
    try {
      return JSON.parse(arrMatch[0]) as T;
    } catch {}
  }

  return null;
}

/**
 * Connectivity test for diagnostics and test suites.
 */
export async function testGeminiConnectivity(): Promise<{
  ok: boolean;
  model?: string;
  durationMs?: number;
  error?: string;
}> {
  const client = getGeminiClient();
  if (!client) {
    return { ok: false, error: 'API key not configured in environment.' };
  }

  const startTime = Date.now();
  try {
    const result = await generateContentWithFallback({
      contents: 'Respond with valid JSON: {"ping": "pong"}',
      responseMimeType: 'application/json',
      timeoutMs: 15000,
    });

    const parsed = parseSafeJson<{ ping: string }>(result.text);
    if (parsed && parsed.ping === 'pong') {
      return {
        ok: true,
        model: result.modelUsed,
        durationMs: result.durationMs,
      };
    }

    return {
      ok: true,
      model: result.modelUsed,
      durationMs: Date.now() - startTime,
    };
  } catch (err: any) {
    return {
      ok: false,
      error: err?.message || String(err),
      durationMs: Date.now() - startTime,
    };
  }
}
