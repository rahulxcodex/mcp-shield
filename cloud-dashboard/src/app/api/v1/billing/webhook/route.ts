import { NextResponse } from 'next/server';
import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';
import { idempotencyStore } from '@/lib/idempotency';
import { sanitizeApiError } from '@/lib/errors';
import crypto from 'crypto';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_dummyKeyForBuild', {
  apiVersion: '2026-08-26.dahlia',
});

const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
const rzpWebhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || '';

// Initialize Supabase admin client to bypass RLS for webhook operations
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://dummy.supabase.co',
  process.env.SUPABASE_SERVICE_ROLE_KEY || 'dummy_key'
);

export async function POST(req: Request) {
  const body = await req.text();
  const stripeSig = req.headers.get('stripe-signature');
  const rzpSig = req.headers.get('x-razorpay-signature');

  // 1. Handle Stripe Webhook
  if (stripeSig) {
    let event: Stripe.Event;

    try {
      event = stripe.webhooks.constructEvent(body, stripeSig, endpointSecret);
    } catch (err: any) {
      console.error(`[STRIPE_WEBHOOK] Error: ${err.message}`);
      return NextResponse.json({ error: `Webhook signature verification failed: ${err.message}` }, { status: 400 });
    }

    // Idempotency: avoid double-processing the same webhook event
    if (!idempotencyStore.acquire(`stripe_event:${event.id}`)) {
      return NextResponse.json({ received: true, alreadyProcessed: true });
    }

    try {
      switch (event.type) {
        case 'checkout.session.completed': {
          const session = event.data.object as Stripe.Checkout.Session;
          const organizationId = session.metadata?.organizationId || session.client_reference_id;
          const plan = session.metadata?.plan || 'pro';
          const seats = Number(session.metadata?.seats) || (plan === 'enterprise' ? 25 : 5);
          
          if (organizationId) {
            const { error } = await supabaseAdmin
              .from('organizations')
              .update({
                plan,
                max_seats: seats,
                updated_at: new Date().toISOString()
              })
              .eq('id', organizationId);
              
            if (error) {
              console.error('[STRIPE_WEBHOOK] Database update failed:', error);
              idempotencyStore.release(`stripe_event:${event.id}`);
              return NextResponse.json({ error: 'Database update failed, retry permitted' }, { status: 500 });
            }
          }
          break;
        }
        case 'customer.subscription.updated': {
          const subscription = event.data.object as Stripe.Subscription;
          const organizationId = subscription.metadata?.organizationId;
          const plan = subscription.metadata?.plan || 'pro';
          const seats = Number(subscription.metadata?.seats) || 5;

          if (organizationId && subscription.status === 'active') {
            await supabaseAdmin
              .from('organizations')
              .update({ plan, max_seats: seats, updated_at: new Date().toISOString() })
              .eq('id', organizationId);
          }
          break;
        }
        case 'customer.subscription.deleted': {
          const subscription = event.data.object as Stripe.Subscription;
          const organizationId = subscription.metadata?.organizationId;
          if (organizationId) {
            await supabaseAdmin
              .from('organizations')
              .update({ plan: 'community', max_seats: 1, updated_at: new Date().toISOString() })
              .eq('id', organizationId);
          }
          break;
        }
        default:
          break;
      }
    } catch (err: unknown) {
      return sanitizeApiError(err, 'Webhook processing error');
    }

    return NextResponse.json({ received: true });
  }

  // 2. Handle Razorpay Webhook
  if (rzpSig && rzpWebhookSecret) {
    const expectedSig = crypto
      .createHmac('sha256', rzpWebhookSecret)
      .update(body)
      .digest('hex');

    const bufA = Buffer.from(expectedSig, 'hex');
    const bufB = Buffer.from(rzpSig, 'hex');
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
      return NextResponse.json({ error: 'Invalid Razorpay webhook signature' }, { status: 400 });
    }

    try {
      const payload = JSON.parse(body);
      const eventType = payload.event;
      const paymentEntity = payload.payload?.payment?.entity;
      const notes = paymentEntity?.notes || {};
      const paymentId = paymentEntity?.id;

      if (paymentId && !idempotencyStore.acquire(`rzp_webhook_evt:${paymentId}`)) {
        return NextResponse.json({ received: true, alreadyProcessed: true });
      }

      if (eventType === 'payment.captured' || eventType === 'order.paid') {
        const organizationId = notes.organizationId;
        const plan = notes.plan || 'pro';
        const seats = Number(notes.seats) || (plan === 'enterprise' ? 25 : 5);

        if (organizationId) {
          await supabaseAdmin
            .from('organizations')
            .update({ plan, max_seats: seats, updated_at: new Date().toISOString() })
            .eq('id', organizationId);
        }
      }
    } catch (err: unknown) {
      return sanitizeApiError(err, 'Razorpay webhook processing error');
    }

    return NextResponse.json({ received: true });
  }

  return NextResponse.json({ error: 'Missing webhook signature headers' }, { status: 400 });
}

