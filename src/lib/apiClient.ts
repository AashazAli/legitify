// ==============================================================================
// LEGITIFY CENTRALIZED RESILIENT API CLIENT
// Strict Content-Type Inspection, Base64 Stream-Safe Transport, Zero Unhandled JSON Crashes
// ==============================================================================
import { LegitifyReport, ScanRecord } from '../types';

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  scan_id?: string;
  report?: LegitifyReport;
  scans?: ScanRecord[];
  answer?: string;
  error?: {
    code: string;
    message: string;
    retryable?: boolean;
  } | string;
  requestId?: string;
}

export class LegitifyApiError extends Error {
  code: string;
  retryable: boolean;
  requestId?: string;

  constructor(message: string, code: string = 'UNKNOWN_ERROR', retryable: boolean = false, requestId?: string) {
    super(message);
    this.name = 'LegitifyApiError';
    this.code = code;
    this.retryable = retryable;
    this.requestId = requestId;
  }
}

function resolveApiBase(): string {
  if (typeof window !== 'undefined') {
    const env = (import.meta as any).env || {};
    const envUrl = env.VITE_API_URL || env.VITE_API_BASE_URL;
    if (envUrl && !envUrl.includes('localhost') && !envUrl.includes('127.0.0.1') && envUrl !== '/api') {
      return envUrl.replace(/\/$/, '');
    }
    return '/api';
  }
  return '/api';
}

export const API_BASE = resolveApiBase();

export async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      const base64 = result.split(',')[1] || result;
      resolve(base64);
    };
    reader.onerror = (err) => reject(err);
    reader.readAsDataURL(file);
  });
}

export async function safeFetch<T = any>(endpoint: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
  const requestId = `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  const headers = new Headers(options.headers || {});
  headers.set('X-Request-ID', requestId);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 45000); // 45s for deep dual AI model scan

  try {
    const res = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const contentType = res.headers.get('content-type') || '';
    const rawText = await res.text();

    if (!contentType.includes('application/json')) {
      console.warn(`[API] Non-JSON response from ${endpoint} (Status ${res.status}):`, rawText.slice(0, 200));
      throw new LegitifyApiError(
        'LEGITIFY verification service is processing your request. Please retry in a moment.',
        'SERVICE_UNAVAILABLE',
        true,
        requestId
      );
    }

    let json: ApiResponse<T>;
    try {
      json = JSON.parse(rawText);
    } catch {
      throw new LegitifyApiError(
        'LEGITIFY verification service returned an invalid format. Please retry.',
        'INVALID_JSON_RESPONSE',
        true,
        requestId
      );
    }

    if (!res.ok || json.success === false) {
      const errObj = typeof json.error === 'object' ? json.error : null;
      const message = errObj?.message || (typeof json.error === 'string' ? json.error : `Request failed with status ${res.status}`);
      const code = errObj?.code || `HTTP_${res.status}`;
      const retryable = errObj?.retryable ?? (res.status >= 500);
      throw new LegitifyApiError(message, code, retryable, requestId);
    }

    return json;
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err instanceof LegitifyApiError) throw err;
    if (err.name === 'AbortError') {
      throw new LegitifyApiError('Request timed out. The verification pipeline took longer than expected.', 'TIMEOUT', true, requestId);
    }
    throw new LegitifyApiError(err?.message || 'Network connection failed. Please check your internet.', 'NETWORK_ERROR', true, requestId);
  }
}
