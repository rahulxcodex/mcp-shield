/**
 * MCP Shield - Support & Complaint Google Apps Script Web App
 * 
 * Deployment Instructions:
 * 1. Open https://script.google.com and create a new project.
 * 2. Paste this code into Code.gs.
 * 3. Click Deploy -> New deployment.
 * 4. Select type: 'Web app'.
 * 5. Set 'Execute as': 'Me' (your Google account).
 * 6. Set 'Who has access': 'Anyone'.
 * 7. Copy the generated Web App URL and set it in your environment:
 *    APPS_SCRIPT_WEBHOOK_URL="https://script.google.com/macros/s/AKfycbx.../exec"
 */

const RECIPIENT_EMAIL = 'rahulr24g@gmail.com';

function doPost(e) {
  try {
    const rawData = e.postData ? e.postData.contents : '{}';
    const payload = JSON.parse(rawData);

    const type = payload.type || 'Complaint';
    const name = payload.name || 'Anonymous User';
    const userEmail = payload.email || 'no-reply@example.com';
    const subject = payload.subject || 'MCP Shield Support Inquiry';
    const message = payload.message || 'No description provided';
    const priority = payload.priority || 'Medium';
    const ticketId = 'MCP-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const timestamp = new Date().toLocaleString();

    // Priority color formatting
    const priorityColor = priority === 'Critical' ? '#ef4444' : priority === 'High' ? '#f97316' : '#10b981';

    const emailSubject = `[MCP-SHIELD ${type.toUpperCase()}] ${ticketId}: ${subject}`;

    const htmlBody = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #090a0f; color: #f1f5f9; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b;">
        <div style="background: linear-gradient(135deg, #10b981, #06b6d4); padding: 24px; text-align: left;">
          <h1 style="margin: 0; font-size: 20px; color: #000; font-weight: 800; letter-spacing: -0.5px;">🛡️ MCP-SHIELD SUPPORT DISPATCH</h1>
          <p style="margin: 4px 0 0 0; color: #064e3b; font-size: 13px; font-weight: 600;">Incoming ${type} Alert</p>
        </div>
        
        <div style="padding: 24px;">
          <div style="display: flex; margin-bottom: 20px; border-bottom: 1px solid #1e293b; padding-bottom: 16px;">
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
              <tr>
                <td style="color: #94a3b8; padding: 6px 0; width: 120px;">Ticket ID:</td>
                <td style="color: #38bdf8; font-family: monospace; font-weight: bold;">${ticketId}</td>
              </tr>
              <tr>
                <td style="color: #94a3b8; padding: 6px 0;">Inquiry Type:</td>
                <td style="color: #f1f5f9; font-weight: 600;">${type}</td>
              </tr>
              <tr>
                <td style="color: #94a3b8; padding: 6px 0;">Priority:</td>
                <td><span style="background-color: ${priorityColor}22; color: ${priorityColor}; padding: 2px 8px; border-radius: 4px; font-weight: bold; border: 1px solid ${priorityColor}44;">${priority}</span></td>
              </tr>
              <tr>
                <td style="color: #94a3b8; padding: 6px 0;">Sender Name:</td>
                <td style="color: #f1f5f9;">${name}</td>
              </tr>
              <tr>
                <td style="color: #94a3b8; padding: 6px 0;">Sender Email:</td>
                <td><a href="mailto:${userEmail}" style="color: #10b981; text-decoration: none;">${userEmail}</a></td>
              </tr>
              <tr>
                <td style="color: #94a3b8; padding: 6px 0;">Timestamp:</td>
                <td style="color: #64748b;">${timestamp}</td>
              </tr>
            </table>
          </div>

          <div style="margin-top: 16px;">
            <h3 style="margin: 0 0 8px 0; font-size: 14px; color: #cbd5e1; text-transform: uppercase; letter-spacing: 0.5px;">Subject</h3>
            <p style="margin: 0 0 16px 0; font-size: 15px; color: #fff; font-weight: bold;">${subject}</p>
          </div>

          <div style="margin-top: 16px;">
            <h3 style="margin: 0 0 8px 0; font-size: 14px; color: #cbd5e1; text-transform: uppercase; letter-spacing: 0.5px;">Message / Complaint Details</h3>
            <div style="background-color: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid #1e293b; color: #e2e8f0; font-size: 14px; line-height: 1.6; white-space: pre-wrap;">${message}</div>
          </div>
        </div>

        <div style="background-color: #0b0f19; padding: 16px 24px; text-align: center; border-top: 1px solid #1e293b; font-size: 12px; color: #64748b;">
          This email was dispatched via Google Apps Script integration for MCP Shield Security Gateway.
        </div>
      </div>
    `;

    // Send email using GmailApp or MailApp
    MailApp.sendEmail({
      to: RECIPIENT_EMAIL,
      subject: emailSubject,
      htmlBody: htmlBody,
      replyTo: userEmail
    });

    // Optionally append to bound sheet if active
    try {
      const sheet = SpreadsheetApp.getActiveSpreadsheet();
      if (sheet) {
        let logSheet = sheet.getSheetByName('Support_Logs');
        if (!logSheet) {
          logSheet = sheet.insertSheet('Support_Logs');
          logSheet.appendRow(['Ticket ID', 'Timestamp', 'Type', 'Priority', 'Name', 'Email', 'Subject', 'Message']);
        }
        logSheet.appendRow([ticketId, timestamp, type, priority, name, userEmail, subject, message]);
      }
    } catch (sheetErr) {
      // Standalone script without bound sheet; harmless ignore
    }

    return ContentService.createTextOutput(JSON.stringify({
      success: true,
      ticketId: ticketId,
      message: 'Support notification dispatched to administrator'
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: 'online',
    service: 'MCP Shield Support Mailer'
  })).setMimeType(ContentService.MimeType.JSON);
}
