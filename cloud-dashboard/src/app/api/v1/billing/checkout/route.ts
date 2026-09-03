import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import Stripe from 'stripe';

const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeKey ? new Stripe(stripeKey, {
  apiVersion: '2026-08-26.dahlia',
}) : null;

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    if (error || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    let { priceId, organizationId, plan = 'pro', seats = 25 } = body;

    // Enforce organization membership and role authorization
    if (organizationId) {
      const { data: member } = await supabase
        .from('organization_members')
        .select('organization_id, role')
        .eq('user_id', user.id)
        .eq('organization_id', organizationId)
        .maybeSingle();

      if (!member || (member.role !== 'owner' && member.role !== 'admin')) {
        return NextResponse.json({ error: 'Forbidden: Owner or Admin role required' }, { status: 403 });
      }
    } else {
      const { data: orgs } = await supabase
        .from('organization_members')
        .select('organization_id, role')
        .eq('user_id', user.id)
        .in('role', ['owner', 'admin'])
        .limit(1);
      organizationId = orgs?.[0]?.organization_id || '00000000-0000-0000-0000-000000000000';
    }

    const isMockStripe = !stripeKey || !stripe;

    if (isMockStripe) {
      // Simulate successful checkout for test/demo environments
      try {
        await supabase
          .from('organizations')
          .update({
            plan,
            max_seats: plan === 'enterprise' ? Number(seats) || 25 : 5
          })
          .eq('id', organizationId);
      } catch {}

      return NextResponse.json({
        url: `${process.env.NEXT_PUBLIC_APP_URL || ''}/settings/billing?success=true&plan=${plan}&seats=${seats}`,
        simulation: true
      });
    }

    const allowedSeats = [25, 50, 100, 500, 1000];
    const validSeats = allowedSeats.includes(Number(seats)) ? Number(seats) : 25;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId || (plan === 'enterprise' ? 'price_mcp_enterprise_monthly' : 'price_mcp_pro_monthly'),
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/settings/billing?success=true`,
      cancel_url: `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/settings/billing?canceled=true`,
      client_reference_id: organizationId,
      metadata: {
        organizationId: organizationId,
        userId: user.id,
        plan,
        seats: String(validSeats)
      }
    });

    return NextResponse.json({ url: session.url });
  } catch (error: any) {
    console.error('Checkout error:', error);
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 });
  }
}
