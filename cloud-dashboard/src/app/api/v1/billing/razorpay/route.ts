import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import crypto from 'crypto';

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    if (error || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    const { action, organizationId, plan = 'pro', seats = 25, razorpay_payment_id, razorpay_order_id, razorpay_signature } = body;

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
      if (keySecret && razorpay_order_id && razorpay_payment_id && razorpay_signature) {
        const expectedSignature = crypto
          .createHmac('sha256', keySecret)
          .update(`${razorpay_order_id}|${razorpay_payment_id}`)
          .digest('hex');

        if (expectedSignature !== razorpay_signature) {
          return NextResponse.json({ error: 'Invalid payment signature' }, { status: 400 });
        }
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
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Internal error' }, { status: 500 });
  }
}
