import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_dummyKeyForBuild', {
  apiVersion: '2026-08-26.dahlia',
});

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    if (error || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    let { priceId, organizationId } = body;

    // Find organization if not explicitly supplied
    if (!organizationId) {
      const { data: orgs } = await supabase
        .from('organization_members')
        .select('organization_id')
        .eq('user_id', user.id)
        .limit(1);
      organizationId = orgs?.[0]?.organization_id || '00000000-0000-0000-0000-000000000000';
    }

    const stripeKey = process.env.STRIPE_SECRET_KEY;
    const isMockStripe = !stripeKey || stripeKey === 'sk_test_dummyKeyForBuild';

    if (isMockStripe) {
      // Simulate successful checkout for test/demo environments
      try {
        await supabase
          .from('organizations')
          .update({ plan: 'pro' })
          .eq('id', organizationId);
      } catch {}

      return NextResponse.json({
        url: `${process.env.NEXT_PUBLIC_APP_URL || ''}/settings/billing?success=true&plan=pro`,
        simulation: true
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId || 'price_mcp_pro_monthly',
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/settings/billing?success=true`,
      cancel_url: `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/settings/billing?canceled=true`,
      client_reference_id: organizationId,
      metadata: {
        organizationId: organizationId,
        userId: user.id
      }
    });

    return NextResponse.json({ url: session.url });
  } catch (error: any) {
    console.error('Checkout error:', error);
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 });
  }
}
