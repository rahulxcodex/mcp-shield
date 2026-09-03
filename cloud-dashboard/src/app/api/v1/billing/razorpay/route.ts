import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { idempotencyStore } from '@/lib/idempotency';
import { sanitizeApiError } from '@/lib/errors';
import crypto from 'crypto';

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    if (error || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Rate limiting: 10 billing requests per minute per user/IP
    const clientIp = getClientIp(req);
    const rlCheck = globalRateLimiter.check(`billing_rzp:${user.id}:${clientIp}`, 10, 60 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Too many billing requests. Please try again in a minute.' }, { status: 429 });
    }

    const body = await req.json().catch(() => ({}));
    let { action, organizationId, plan = 'pro', seats = 25, razorpay_payment_id, razorpay_order_id, razorpay_signature } = body;

    // Server-side verification of organization ownership / admin role
    if (organizationId) {
      const { data: member } = await supabase
        .from('organization_members')
        .select('organization_id, role')
        .eq('user_id', user.id)
        .eq('organization_id', organizationId)
        .maybeSingle();

      if (!member || (member.role !== 'owner' && member.role !== 'admin')) {
        return NextResponse.json({ error: 'Forbidden: Owner or Admin role required for this organization' }, { status: 403 });
      }
    } else {
      const { data: orgs } = await supabase
        .from('organization_members')
        .select('organization_id, role')
        .eq('user_id', user.id)
        .in('role', ['owner', 'admin'])
        .limit(1);
      organizationId = orgs?.[0]?.organization_id;
      if (!organizationId) {
        return NextResponse.json({ error: 'No organization found where you have owner or admin privileges' }, { status: 403 });
      }
    }

    const keyId = process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID || process.env.RAZORPAY_KEY_ID;
    const keySecret = process.env.RAZORPAY_KEY_SECRET;

    // Multi-seat enterprise tier pricing in INR
    const enterpriseSeatTiers: Record<number, number> = {
      25: 39900,
      50: 69900,
      100: 119900,
      500: 399900,
      1000: 699900,
    };
    const numSeats = Number(seats) || 25;
    const amount = plan === 'enterprise'
      ? (enterpriseSeatTiers[numSeats] || 39900)
      : 2400;

    if (action === 'create-order') {
      if (!keyId || !keySecret) {
        // Simulation order for staging/demo environments
        return NextResponse.json({
          orderId: `order_sim_${Date.now()}`,
          amount: amount * 100,
          currency: 'INR',
          keyId: keyId || 'rzp_test_placeholder',
          simulation: true,
          plan,
          seats: numSeats
        });
      }

      // Call Razorpay API to create real order
      const auth = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
      const rzpRes = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          amount: amount * 100, // in paise
          currency: 'INR',
          receipt: `rcpt_${Date.now()}`,
          notes: {
            organizationId,
            userId: user.id,
            plan,
            seats: String(numSeats)
          }
        })
      });

      if (!rzpRes.ok) {
        const errData = await rzpRes.json().catch(() => ({}));
        return NextResponse.json({ error: errData.error?.description || 'Failed to create Razorpay order' }, { status: 400 });
      }

      const orderData = await rzpRes.json();
      return NextResponse.json({
        orderId: orderData.id,
        amount: orderData.amount,
        currency: orderData.currency,
        keyId,
        plan,
        seats: numSeats
      });
    }

    if (action === 'verify-payment') {
      // STRICT FAIL-CLOSED VERIFICATION: Reject if any signature parameter is missing
      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return NextResponse.json({
          error: 'Payment verification failed: missing razorpay_order_id, razorpay_payment_id, or razorpay_signature'
        }, { status: 400 });
      }

      if (!keySecret) {
        // In local/test environment where secrets are omitted, allow test order IDs only
        const isDev = process.env.NODE_ENV !== 'production';
        if (!isDev || !razorpay_order_id.startsWith('order_sim_')) {
          return NextResponse.json({ error: 'Razorpay secret key not configured on server (fail-closed)' }, { status: 500 });
        }
      } else {
        const expectedSignature = crypto
          .createHmac('sha256', keySecret)
          .update(`${razorpay_order_id}|${razorpay_payment_id}`)
          .digest('hex');

        const bufA = Buffer.from(expectedSignature, 'hex');
        const bufB = Buffer.from(razorpay_signature, 'hex');
        if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
          return NextResponse.json({ error: 'Invalid payment signature: verification failed' }, { status: 400 });
        }
      }

      // Idempotency protection: prevent duplicate upgrades for the same payment
      const isNewPayment = idempotencyStore.acquire(`rzp_payment:${razorpay_payment_id}`, {
        organizationId,
        plan,
        seats: numSeats
      });

      if (!isNewPayment) {
        return NextResponse.json({
          success: true,
          alreadyProcessed: true,
          plan: plan || 'pro',
          seats: numSeats
        });
      }

      // Upgrade organization plan and seats in database
      if (organizationId) {
        await supabase
          .from('organizations')
          .update({
            plan: plan || 'pro',
            max_seats: plan === 'enterprise' ? numSeats : 5
          })
          .eq('id', organizationId);
      }

      return NextResponse.json({ success: true, plan: plan || 'pro', seats: numSeats });
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to process payment');
  }
}

