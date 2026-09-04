export interface SupportEmailPayload {
  ticketId: string;
  name: string;
  email: string;
  type: string;
  priority: string;
  subject: string;
  message: string;
  recipient: string;
  timestamp?: string;
}

export interface EmailDispatchResult {
  success: boolean;
  provider: 'resend' | 'sendgrid' | 'apps_script' | 'logged_only';
  messageId?: string;
  error?: string;
}

export function generateSupportEmailHtml(payload: SupportEmailPayload): string {
  const priorityColor =
    payload.priority === 'Critical'
      ? '#ef4444'
      : payload.priority === 'High'
      ? '#f97316'
      : '#10b981';

  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>MCP-Shield Support Alert</title>
  </head>
  <body style="margin: 0; padding: 24px; background-color: #090a0f; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f1f5f9;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #0f172a; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);">
      <div style="background: linear-gradient(135deg, #10b981 0%, #06b6d4 100%); padding: 24px;">
        <h1 style="margin: 0; font-size: 20px; color: #000; font-weight: 800; letter-spacing: -0.5px;">??? MCP-SHIELD SECURITY SUPPORT</h1>
        <p style="margin: 4px 0 0 0; color: #064e3b; font-size: 13px; font-weight: 600;">Incoming ${payload.type.toUpperCase()} Notification</p>
      </div>
      
      <div style="padding: 24px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px; border-bottom: 1px solid #1e293b; padding-bottom: 16px;">
          <tr>
            <td style="color: #94a3b8; padding: 6px 0; width: 130px;">Ticket ID:</td>
            <td style="color: #38bdf8; font-family: monospace; font-weight: bold; font-size: 14px;">${payload.ticketId}</td>
          </tr>
          <tr>
            <td style="color: #94a3b8; padding: 6px 0;">Inquiry Type:</td>
            <td style="color: #f1f5f9; font-weight: 600;">${payload.type}</td>
          </tr>
          <tr>
            <td style="color: #94a3b8; padding: 6px 0;">Priority:</td>
            <td><span style="background-color: ${priorityColor}22; color: ${priorityColor}; padding: 2px 8px; border-radius: 4px; font-weight: bold; border: 1px solid ${priorityColor}44;">${payload.priority}</span></td>
          </tr>
          <tr>
            <td style="color: #94a3b8; padding: 6px 0;">Sender Name:</td>
            <td style="color: #f1f5f9;">${payload.name}</td>
          </tr>
          <tr>
            <td style="color: #94a3b8; padding: 6px 0;">Sender Email:</td>
            <td><a href="mailto:${payload.email}" style="color: #38bdf8; text-decoration: none;">${payload.email}</a></td>
          </tr>
          <tr>
            <td style="color: #94a3b8; padding: 6px 0;">Submitted At:</td>
            <td style="color: #94a3b8;">${payload.timestamp || new Date().toUTCString()}</td>
          </tr>
        </table>

        <div style="margin-bottom: 24px;">
          <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 6px; font-weight: 700;">Subject</div>
          <div style="font-size: 16px; font-weight: bold; color: #f8fafc; background-color: #1e293b; padding: 12px; border-radius: 8px; border-left: 4px solid #38bdf8;">
            ${payload.subject}
          </div>
        </div>

        <div style="margin-bottom: 24px;">
          <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 6px; font-weight: 700;">Inquiry / Complaint Details</div>
          <div style="font-size: 14px; line-height: 1.6; color: #cbd5e1; background-color: #1e293b; padding: 16px; border-radius: 8px; white-space: pre-wrap; word-break: break-word;">
${payload.message}
          </div>
        </div>

        <div style="border-top: 1px solid #1e293b; padding-top: 16px; display: flex; justify-content: space-between; font-size: 11px; color: #64748b;">
          <span>MCP-Shield Capability Broker</span>
          <span>Zero-Trust Security Gateway</span>
        </div>
      </div>
    </div>
  </body>
  </html>
  `;
}

export async function sendSupportEmail(payload: SupportEmailPayload): Promise<EmailDispatchResult> {
  const emailSubject = `[MCP-SHIELD ${payload.type.toUpperCase()}] ${payload.ticketId}: ${payload.subject}`;
  const html = generateSupportEmailHtml(payload);
  const targetRecipient = payload.recipient || process.env.SUPPORT_ROUTING_EMAIL || 'support@mcpshield.com';

  // 1. Primary: Resend REST API (https://resend.com)
  const resendApiKey = process.env.RESEND_API_KEY;
  if (resendApiKey) {
    try {
      const fromAddress = process.env.EMAIL_FROM || 'MCP Shield Support <onboarding@resend.dev>';
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: fromAddress,
          to: [targetRecipient],
          reply_to: payload.email,
          subject: emailSubject,
          html: html
        })
      });

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        return {
          success: true,
          provider: 'resend',
          messageId: data.id
        };
      } else {
        const errText = await res.text().catch(() => 'Unknown error');
        console.warn('[EMAIL_SERVICE] Resend API responded with error:', res.status, errText);
      }
    } catch (err) {
      console.warn('[EMAIL_SERVICE] Resend network error:', err);
    }
  }

  // 2. Secondary: SendGrid v3 Mail API
  const sendgridApiKey = process.env.SENDGRID_API_KEY;
  if (sendgridApiKey) {
    try {
      const fromAddress = process.env.EMAIL_FROM || 'support@mcpshield.com';
      const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sendgridApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          personalizations: [{
            to: [{ email: targetRecipient }]
          }],
          from: { email: fromAddress, name: 'MCP Shield Support' },
          reply_to: { email: payload.email, name: payload.name },
          subject: emailSubject,
          content: [{
            type: 'text/html',
            value: html
          }]
        })
      });

      if (res.ok || res.status === 202) {
        return {
          success: true,
          provider: 'sendgrid'
        };
      } else {
        const errText = await res.text().catch(() => 'Unknown error');
        console.warn('[EMAIL_SERVICE] SendGrid API error:', res.status, errText);
      }
    } catch (err) {
      console.warn('[EMAIL_SERVICE] SendGrid network error:', err);
    }
  }

  // 3. Fallback: Google Apps Script Webhook
  const appsScriptUrl = process.env.APPS_SCRIPT_WEBHOOK_URL;
  if (appsScriptUrl) {
    try {
      const scriptRes = await fetch(appsScriptUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ticketId: payload.ticketId,
          name: payload.name,
          email: payload.email,
          type: payload.type,
          priority: payload.priority,
          subject: payload.subject,
          message: payload.message,
          recipient: targetRecipient,
          timestamp: payload.timestamp || new Date().toISOString()
        })
      });

      if (scriptRes.ok) {
        return {
          success: true,
          provider: 'apps_script'
        };
      }
    } catch (err) {
      console.warn('[EMAIL_SERVICE] Apps Script fallback warning:', err);
    }
  }

  // 4. Logged Only (Development / Unconfigured Email Provider)
  console.log(`[EMAIL_SERVICE_LOG] Ticket: ${payload.ticketId} | To: ${targetRecipient} | From: ${payload.email} | Subject: ${payload.subject}`);
  return {
    success: true,
    provider: 'logged_only'
  };
}
