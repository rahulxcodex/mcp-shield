import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '', {
  apiVersion: '2025-02-24.acacia',
});

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error } = await supabase.auth.getUser();

    if (error || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json();
    const { priceId, organizationId } = body;

    if (!priceId || !organizationId) {
      return NextResponse.json({ error: 'Missing priceId or organizationId' }, { status: 400 });
    }

    // Check if user is a member of the organization
    const { data: memberData, error: memberError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', user.id)
      .single();

    if (memberError || !memberData) {
      return NextResponse.json({ error: 'Not authorized for this organization' }, { status: 403 });
    }

    if (memberData.role !== 'owner' && memberData.role !== 'admin') {
      return NextResponse.json({ error: 'Must be an owner or admin to manage billing' }, { status: 403 });
    }

    // Optional: Get or create Stripe customer for the organization
    // Let's pass the organization_id in client_reference_id or metadata
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/dashboard/${organizationId}/billing?success=true`,
      cancel_url: `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/dashboard/${organizationId}/billing?canceled=true`,
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
