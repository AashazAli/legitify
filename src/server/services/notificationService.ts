// ==============================================================================
// LEGITIFY EMAIL NOTIFICATION SERVICE (RESEND API INTEGRATION)
// ==============================================================================
import { LegitifyReport } from '../../types';

export interface SendReportNotificationParams {
  toEmail: string;
  recipientName?: string;
  report: LegitifyReport;
}

export async function sendReportNotificationEmail(params: SendReportNotificationParams): Promise<{ success: boolean; messageId?: string; error?: string }> {
  const resendApiKey = process.env.RESEND_API_KEY;
  if (!resendApiKey || !resendApiKey.startsWith('re_')) {
    return { success: false, error: 'RESEND_API_KEY is not configured' };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const emailSubject = `[LEGITIFY ALERT] Investigation Dossier: ${params.report.entity_name} (${params.report.verdict})`;
    const emailHtml = `
      <div style="background: #07090D; color: #F1F5F9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px; border-radius: 8px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #00C880; margin-top: 0;">🛡️ LEGITIFY Trust Intelligence Alert</h2>
        <p>Dear ${params.recipientName || 'Applicant'},</p>
        <p>Your requested forensic verification scan for <strong>${params.report.entity_name}</strong> has completed.</p>
        
        <div style="background: #0D1117; border: 1px solid #1E2B3A; border-radius: 8px; padding: 16px; margin: 20px 0;">
          <div style="font-size: 13px; color: #94A3B8; text-transform: uppercase;">Final Verdict</div>
          <div style="font-size: 20px; font-weight: bold; color: ${params.report.trust_score < 40 ? '#EF4444' : params.report.trust_score < 70 ? '#F59E0B' : '#00C880'}; margin: 4px 0 12px 0;">
            ${params.report.verdict} (Trust Score: ${params.report.trust_score}/100)
          </div>
          <div style="font-size: 13px; color: #CBD5E1;">
            <strong>Executive Summary:</strong> ${params.report.executive_summary}
          </div>
        </div>

        <div style="margin-top: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #1E2B3A; padding-top: 12px;">
          Case Reference ID: ${params.report.scan_id}<br/>
          Verified by: MCA Registry, DNS RDAP, VirusTotal, Google Safe Browsing, AbuseIPDB, Kaggle Supervised ML.
        </div>
      </div>
    `;

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'LEGITIFY Alerts <onboarding@resend.dev>',
        to: [params.toEmail],
        subject: emailSubject,
        html: emailHtml,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data: any = await res.json();
      return { success: true, messageId: data.id };
    } else {
      const errText = await res.text();
      return { success: false, error: errText };
    }
  } catch (err: any) {
    return { success: false, error: err?.message || 'Failed to dispatch email' };
  }
}
