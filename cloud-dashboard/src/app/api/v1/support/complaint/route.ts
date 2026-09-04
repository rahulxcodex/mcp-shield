import { NextResponse } from 'next/server';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { sanitizeApiError } from '@/lib/errors';
import { sendSupportEmail } from '@/lib/email-service';
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

    // Strict input validation & size bounding
    if (!email || typeof email !== 'string' || !email.includes('@') || email.length > 254) {
      return NextResponse.json({ error: 'Valid email address is required (max 254 chars).' }, { status: 400 });
    }

    if (!subject || typeof subject !== 'string' || subject.trim().length === 0 || subject.length > 200) {
      return NextResponse.json({ error: 'Subject is required and must not exceed 200 characters.' }, { status: 400 });
    }

    if (!message || typeof message !== 'string' || message.trim().length === 0 || message.length > 5000) {
      return NextResponse.json({ error: 'Message is required and must not exceed 5000 characters.' }, { status: 400 });
    }

    const safeName = typeof name === 'string' ? name.slice(0, 100) : 'Anonymous';
    const ticketId = `MCP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const targetEmail = process.env.SUPPORT_ROUTING_EMAIL || 'support@mcpshield.com';

    const dispatchResult = await sendSupportEmail({
      ticketId,
      name: safeName,
      email,
      type,
      priority,
      subject,
      message,
      recipient: targetEmail,
      timestamp: new Date().toISOString()
    });

    console.log(`[SUPPORT_TICKET_CREATED] [ID: ${ticketId}] Type: ${type} | Provider: ${dispatchResult.provider} | Recipient: ${targetEmail} | From: ${email} | Subject: ${subject}`);

    return NextResponse.json({
      success: true,
      ticketId,
      provider: dispatchResult.provider,
      recipient: targetEmail,
      message: `Your ${type.toLowerCase()} has been logged and dispatched.`
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to submit complaint/inquiry');
  }
}
