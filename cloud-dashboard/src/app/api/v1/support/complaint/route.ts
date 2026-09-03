import { NextResponse } from 'next/server';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { sanitizeApiError } from '@/lib/errors';
import crypto from 'crypto';

export async function POST(req: Request) {
  try {
    const clientIp = getClientIp(req);
    // Rate limit: 5 inquiries per hour per IP to prevent spam
    const rlCheck = globalRateLimiter.check(`support_complaint:${clientIp}`, 5, 3600 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json(
        { error: 'Rate limit exceeded: Please wait before submitting another complaint or inquiry.' },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const { name, email, type = 'Complaint', priority = 'Medium', subject, message } = body;

    if (!email || !subject || !message) {
      return NextResponse.json(
        { error: 'Missing required fields: email, subject, and message are required.' },
        { status: 400 }
      );
    }

    const ticketId = `MCP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const targetEmail = 'rahulr24g@gmail.com';

    const appsScriptUrl = process.env.APPS_SCRIPT_WEBHOOK_URL;
    let dispatchedViaAppsScript = false;

    if (appsScriptUrl) {
      try {
        const scriptRes = await fetch(appsScriptUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ticketId,
            name: name || 'Anonymous',
            email,
            type,
            priority,
            subject,
            message,
            recipient: targetEmail,
            timestamp: new Date().toISOString()
          })
        });
        if (scriptRes.ok) {
          dispatchedViaAppsScript = true;
        }
      } catch (scriptErr) {
        console.warn('[SUPPORT_DISPATCH] Apps Script forward warning:', scriptErr);
      }
    }

    // Always log receipt on server
    console.log(`[SUPPORT_TICKET_CREATED] [ID: ${ticketId}] Type: ${type} | Recipient: ${targetEmail} | From: ${email} | Subject: ${subject}`);

    return NextResponse.json({
      success: true,
      ticketId,
      dispatchedViaAppsScript,
      recipient: targetEmail,
      message: `Your ${type.toLowerCase()} has been logged and queued for administrative review at ${targetEmail}.`
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to submit complaint/inquiry');
  }
}
