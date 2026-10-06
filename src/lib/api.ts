// ==============================================================================
// LEGITIFY FRONTEND API CLIENT
// Dual-Transport (Base64 JSON + Multipart) with Full InternShield & Gemini Grounding
// ==============================================================================
import { LegitifyReport, ScanRecord } from '../types';
import { safeFetch, fileToBase64, LegitifyApiError } from './apiClient';

function getAuthHeaders(token?: string): HeadersInit {
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export async function runScan(
  input: {
    entityType: string;
    entityValue: string;
    contextText?: string;
    file?: File;
    token?: string;
  } | FormData,
  token?: string
): Promise<{ success: boolean; scan_id: string; report: LegitifyReport }> {
  let entityType = "job_offer";
  let entityValue = "Uploaded Document";
  let contextText = "";
  let fileObj: File | undefined;
  let authToken = token;

  if (input instanceof FormData) {
    entityType = String(input.get('entity_type') || 'job_offer');
    entityValue = String(input.get('entity_value') || 'Uploaded Document');
    contextText = String(input.get('context_text') || '');
    fileObj = input.get('file') as File;
  } else {
    authToken = input.token || token;
    entityType = input.entityType || 'job_offer';
    entityValue = input.entityValue || 'Uploaded Document';
    contextText = input.contextText || '';
    fileObj = input.file;
  }

  let fileBase64: string | undefined;
  let filename: string | undefined;
  let mimeType: string | undefined;

  if (fileObj && fileObj instanceof File) {
    filename = fileObj.name;
    mimeType = fileObj.type || (filename.toLowerCase().endsWith('.pdf') ? 'application/pdf' : 'image/jpeg');
    try {
      fileBase64 = await fileToBase64(fileObj);
    } catch (err) {
      console.warn('[API] File to base64 conversion failed:', err);
    }
  }

  // Transmit as clean Base64 JSON Payload (Serverless-Safe & Stream-Safe)
  const payload = {
    entity_type: entityType,
    entity_value: entityValue,
    context_text: contextText,
    filename,
    mimeType,
    fileBase64,
  };

  const res = await safeFetch<{ scan_id: string; report: LegitifyReport }>('/scans', {
    method: 'POST',
    headers: {
      ...getAuthHeaders(authToken),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const report = res.report || (res.data as any)?.report;
  const scanId = res.scan_id || (res.data as any)?.scan_id || report?.id || `SC-${Date.now()}`;

  if (!report) {
    throw new LegitifyApiError('Verification pipeline did not return a structured report.', 'INVALID_REPORT_DATA');
  }

  return { success: true, scan_id: scanId, report };
}

export async function askCopilot(report: LegitifyReport, question: string, token?: string): Promise<string> {
  const res = await safeFetch<{ answer: string }>('/copilot', {
    method: 'POST',
    headers: {
      ...getAuthHeaders(token),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ question, context: report }),
  });

  const answer = res.answer || (res.data as any)?.answer;
  if (!answer) {
    throw new LegitifyApiError('Copilot reasoning service returned an empty response.', 'EMPTY_COPILOT_RESPONSE');
  }
  return answer;
}

export async function getScans(token?: string): Promise<ScanRecord[]> {
  try {
    const res = await safeFetch<{ scans: ScanRecord[] }>('/scans', {
      headers: getAuthHeaders(token),
    });
    return res.scans || (res.data as any)?.scans || [];
  } catch {
    return [];
  }
}

export async function getScanReport(scanId: string, token?: string): Promise<LegitifyReport | null> {
  try {
    const res = await safeFetch<{ report: LegitifyReport }>(`/scans/${scanId}`, {
      headers: getAuthHeaders(token),
    });
    return res.report || (res.data as any)?.report || null;
  } catch {
    return null;
  }
}

export async function getSharedReport(shareToken: string): Promise<LegitifyReport | null> {
  try {
    const res = await safeFetch<{ report: LegitifyReport }>(`/shared-reports/${shareToken}`);
    return res.report || (res.data as any)?.report || null;
  } catch {
    return null;
  }
}

export async function shareReport(scanId: string, token?: string): Promise<string> {
  const res = await safeFetch<{ share_token: string; token: string }>(`/reports/${scanId}/share`, {
    method: 'POST',
    headers: { ...getAuthHeaders(token), 'Content-Type': 'application/json' },
  });
  return res.data?.share_token || res.data?.token || (res as any).share_token || (res as any).token || `share-${Date.now()}`;
}

export async function getThreatIntel(): Promise<any> {
  try {
    const res = await safeFetch<{ threats: any[]; indicators: any[] }>('/threats');
    return (res as any).threats || res.data?.threats || (res as any).indicators || [];
  } catch {
    return [];
  }
}

export async function getAnalytics(): Promise<any> {
  try {
    const res = await safeFetch<{ stats: any; analytics: any }>('/analytics');
    return res.data?.stats || res.data?.analytics || (res as any).stats || (res as any).analytics || null;
  } catch {
    return null; // Backend unavailable — caller must show "Analytics unavailable" message
  }
}

export const getPlatformAnalytics = getAnalytics;

export async function getAuditLogs(token?: string): Promise<any[]> {
  try {
    const res = await safeFetch<{ logs: any[] }>('/audit-logs', { headers: getAuthHeaders(token) });
    return res.data?.logs || (res as any).logs || [];
  } catch {
    return [];
  }
}

export async function getProviderStatuses(): Promise<any> {
  try {
    const res = await safeFetch<{ providers: any }>('/providers/status');
    return res.data?.providers || (res as any).providers || null;
  } catch {
    return null;
  }
}

export async function submitFeedback(scanId: string, rating: number, comment?: string, userId?: string): Promise<void> {
  try {
    await safeFetch('/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, rating, comment, user_id: userId }),
    });
  } catch {}
}
