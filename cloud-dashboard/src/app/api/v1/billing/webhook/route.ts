import { NextResponse } from 'next/server';
import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_dummyKeyForBuild', {
  apiVersion: '2026-08-26.dahlia',
});

const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET || '';

// Initialize Supabase admin client to bypass RLS for webhook operations
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature') as string;

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(body, sig, endpointSecret);
  } catch (err: any) {
    console.error(`Webhook Error: ${err.message}`);
    return NextResponse.json({ error: `Webhook Error: ${err.message}` }, { status: 400 });
  }

  // Handle the event
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      const organizationId = session.metadata?.organizationId || session.client_reference_id;
      
      if (organizationId) {
        // Assume default plan to PRO or based on price ID
        const { error } = await supabaseAdmin
          .from('organizations')
          .update({ plan: 'pro' })
          .eq('id', organizationId);
          
        if (error) {
          console.error('Error updating organization plan:', error);
        }
      }
      break;
    }
    case 'customer.subscription.updated': {
      const subscription = event.data.object as Stripe.Subscription;
      const customerId = subscription.customer as string;
      
      // Real code would map customerId to organizationId, then update plan based on subscription.status
      // Stub implementation for now
      break;
    }
    case 'customer.subscription.deleted': {
      const subscription = event.data.object as Stripe.Subscription;
      const customerId = subscription.customer as string;
      
      // Update plan to 'free' or similar
      break;
    }
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  return NextResponse.json({ received: true });
}
