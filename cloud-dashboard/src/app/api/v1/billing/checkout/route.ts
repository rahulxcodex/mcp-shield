import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { globalRateLimiter, getClientIp } from '@/lib/rate-limiter';
import { sanitizeApiError } from '@/lib/errors';
import Stripe from 'stripe';

const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeKey ? new Stripe(stripeKey, {
  apiVersion: '2026-08-26.dahlia',
}) : null;

// Authoritative Server-Side Plan -> Price Mapping
const SERVER_PLAN_PRICE_MAP: Record<string, Record<number, string> | string> = {
  pro: process.env.STRIPE_PRICE_PRO_MONTHLY || 'price_mcp_pro_monthly',
  enterprise: {
    25: process.env.STRIPE_PRICE_ENT_25 || 'price_mcp_enterprise_25',
    50: process.env.STRIPE_PRICE_ENT_50 || 'price_mcp_enterprise_50',
    100: process.env.STRIPE_PRICE_ENT_100 || 'price_mcp_enterprise_100',
    500: process.env.STRIPE_PRICE_ENT_500 || 'price_mcp_enterprise_500',
    1000: process.env.STRIPE_PRICE_ENT_1000 || 'price_mcp_enterprise_1000',
  }
};

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    if (error || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Rate limiting: 10 checkout creations per minute per user/IP
    const clientIp = getClientIp(req);
    const rlCheck = globalRateLimiter.check(`checkout:${user.id}:${clientIp}`, 10, 60 * 1000);
    if (!rlCheck.allowed) {
      return NextResponse.json({ error: 'Too many checkout attempts. Please wait a minute.' }, { status: 429 });
    }

    const body = await req.json().catch(() => ({}));
    let { organizationId, plan = 'pro', seats = 25 } = body;

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
      organizationId = orgs?.[0]?.organization_id;
      if (!organizationId) {
        return NextResponse.json({ error: 'Forbidden: No organization with admin privileges found' }, { status: 403 });
      }
    }

    const allowedSeats = [25, 50, 100, 500, 1000];
    const validSeats = allowedSeats.includes(Number(seats)) ? Number(seats) : 25;

    // Server-Side Price Resolution (Client-controlled priceId is strictly ignored)
    let authoritativePriceId: string;
    if (plan === 'enterprise') {
      const entPrices = SERVER_PLAN_PRICE_MAP.enterprise as Record<number, string>;
      authoritativePriceId = entPrices[validSeats] || entPrices[25];
    } else {
      authoritativePriceId = SERVER_PLAN_PRICE_MAP.pro as string;
    }

    const isMockStripe = !stripeKey || !stripe;

    if (isMockStripe) {
      // Simulate successful checkout for test/demo environments
      try {
        await supabase
          .from('organizations')
          .update({
            plan,
            max_seats: plan === 'enterprise' ? validSeats : 5
          })
          .eq('id', organizationId);
      } catch {}

      return NextResponse.json({
        url: `${process.env.NEXT_PUBLIC_APP_URL || ''}/settings/billing?success=true&plan=${plan}&seats=${validSeats}`,
        simulation: true
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: authoritativePriceId,
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
  } catch (error: unknown) {
    return sanitizeApiError(error, 'Failed to create checkout session');
  }
}

