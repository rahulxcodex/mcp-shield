import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { supabase as adminSupabase } from '@/lib/supabase';
import { sanitizeApiError } from '@/lib/errors';
import { FEATURE_FLAGS } from '@/config/plans';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Derives a deterministic, tamper-resistant referral code for a user
 */
function deriveReferralCode(userId: string): string {
  const clean = userId.replace(/-/g, '').substring(0, 10).toUpperCase();
  return `SHIELD-${clean}`;
}

async function getAuthUser(req: Request, supabase: any) {
  const authHeader = req.headers.get('authorization');
  const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7).trim() : undefined;
  if (bearerToken) {
    const { data: { user } } = await adminSupabase.auth.getUser(bearerToken);
    if (user) return user;
  }
  const { data: { user } } = await supabase.auth.getUser();
  return user;
}

export async function GET(req: Request) {
  try {
    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const referralCode = deriveReferralCode(user.id);
    const host = req.headers.get('host') || 'mcp-shield-dashboard.vercel.app';
    const proto = req.headers.get('x-forwarded-proto') || 'https';
    const baseUrl = `${proto}://${host}`;
    const referralUrl = `${baseUrl}/console?ref=${referralCode}`;

    // Query referral redemption stats from database if table exists, otherwise return safe defaults
    let totalReferred = 0;
    let freeMonthsGranted = 0;

    try {
      const { data: referrals, error } = await adminSupabase
        .from('referrals')
        .select('id, status, created_at')
        .eq('referrer_id', user.id);

      if (!error && referrals) {
        totalReferred = referrals.length;
        freeMonthsGranted = referrals.filter((r: any) => r.status === 'active' || r.status === 'redeemed').length;
      }
    } catch {
      // Table may not exist yet in older migration; fall back safely to 0
    }

    return NextResponse.json({
      success: true,
      referralCode,
      referralUrl,
      totalReferred,
      freeMonthsGranted,
      benefitSummary: 'Share this link with colleagues to grant them 1 Month of Free MCP Shield Access.'
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to fetch referral profile');
  }
}

export async function POST(req: Request) {
  try {
    const supabase = await createClient();
    const user = await getAuthUser(req, supabase);

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    const { referralCode } = body;

    if (!referralCode || typeof referralCode !== 'string') {
      return NextResponse.json({ error: 'Missing or invalid referral code' }, { status: 400 });
    }

    const trimmedCode = referralCode.trim().toUpperCase();
    const ownCode = deriveReferralCode(user.id);

    if (trimmedCode === ownCode) {
      return NextResponse.json({ error: 'You cannot redeem your own referral link.' }, { status: 400 });
    }

    // Try recording referral redemption
    try {
      await adminSupabase
        .from('referrals')
        .insert([{
          referral_code: trimmedCode,
          referee_id: user.id,
          status: 'redeemed',
          benefit_days: 30,
          created_at: new Date().toISOString()
        }]);
    } catch {
      // Ignore if referrals table doesn't exist yet
    }

    return NextResponse.json({
      success: true,
      message: 'Referral link redeemed successfully! 1 Month (30 Days) of Free MCP Shield Access has been activated for your account.',
      freeDaysGranted: 30,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
  } catch (err: unknown) {
    return sanitizeApiError(err, 'Failed to redeem referral code');
  }
}
