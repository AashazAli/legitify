// ==============================================================================
// AUDIT LOGGING SERVICE
// ==============================================================================
import crypto from 'crypto';
import { supabaseAdmin } from '../../lib/supabase/server';

export interface AuditLogEntry {
  user_id?: string;
  action:
    | "LOGIN_SUCCESS"
    | "LOGIN_FAILED"
    | "LOGOUT"
    | "SCAN_CREATED"
    | "SCAN_STARTED"
    | "SCAN_COMPLETED"
    | "SCAN_FAILED"
    | "REPORT_VIEWED"
    | "REPORT_EXPORTED"
    | "REPORT_SHARED"
    | "FILE_UPLOADED"
    | "FILE_DELETED"
    | "SETTINGS_UPDATED"
    | "ACCOUNT_DELETED";
  resource_type?: string;
  resource_id?: string;
  ip?: string;
  user_agent?: string;
  metadata?: Record<string, any>;
  risk?: "low" | "medium" | "high" | "critical";
}

export async function logAuditEvent(entry: AuditLogEntry): Promise<void> {
  try {
    const ipHash = entry.ip
      ? crypto.createHash('sha256').update(entry.ip).digest('hex').slice(0, 16)
      : undefined;

    // Filter metadata to prevent secrets leaking
    const safeMetadata = { ...(entry.metadata || {}) };
    delete safeMetadata.password;
    delete safeMetadata.token;
    delete safeMetadata.apiKey;
    delete safeMetadata.secret;
    delete safeMetadata.raw_text;

    await supabaseAdmin.from('audit_logs').insert({
      user_id: entry.user_id,
      action: entry.action,
      resource_type: entry.resource_type,
      resource_id: entry.resource_id,
      ip_hash: ipHash,
      user_agent: entry.user_agent ? entry.user_agent.slice(0, 255) : undefined,
      metadata: safeMetadata,
      risk: entry.risk || "low",
    });
  } catch {
    // Logging failure will not interrupt primary execution
  }
}
