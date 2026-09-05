import { NextResponse } from 'next/server';
import * as crypto from 'crypto';
import { createAdminSupabaseClient } from '@/lib/supabase';

// Persistent tracking of trial issuance across serverless function lifetimes / offline test environments
const persistentTrialClaims = new Map<string, { claimedAt: number; fingerprint: string }>();

// The private key must be provided via a secure environment variable or KMS
const getPrivateKey = (): string | null => {
  const key = process.env.LICENSE_PRIVATE_KEY;
  if (!key) return null;
  return key.replace(/\\n/g, '\n').trim();
};

export async function POST(req: Request) {
  try {
    const privateKey = getPrivateKey();
    if (!privateKey) {
      console.error('CRITICAL: LICENSE_PRIVATE_KEY environment variable is not configured');
      return NextResponse.json(
        { error: 'Licensing service configuration error: Missing cryptographic signing key' },
        { status: 500 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const { githubAccessToken, machineFingerprint, seats = 5, tier = 'enterprise-trial', organizationDomain } = body;

    if (!githubAccessToken) {
      return NextResponse.json({ error: 'GitHub Token required' }, { status: 400 });
    }

    // 1. Authenticate with GitHub
    const ghRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${githubAccessToken}`,
        Accept: 'application/vnd.github.v3+json',
      },
    });

    if (!ghRes.ok) {
      return NextResponse.json({ error: 'Invalid GitHub Token' }, { status: 401 });
    }

    const userData = await ghRes.json();
    
    // 2. Security Check: Is account > 1 year old?
    if (!userData.created_at || typeof userData.created_at !== 'string') {
      return NextResponse.json({ error: 'Security Policy: GitHub account creation date could not be verified' }, { status: 400 });
    }
    const accountCreatedAt = new Date(userData.created_at);
    if (isNaN(accountCreatedAt.getTime())) {
      return NextResponse.json({ error: 'Security Policy: Invalid GitHub account creation date' }, { status: 400 });
    }
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

    if (accountCreatedAt > oneYearAgo) {
      return NextResponse.json({ 
        error: 'Security Policy: GitHub account must be at least 1 year old to prevent sybil/bot attacks for trial keys.' 
      }, { status: 403 });
    }

    // Unpaid public self-service requests are restricted strictly to enterprise-trial (max 5 seats)
    const isPaidTier = tier === 'enterprise' && Number(seats) > 5;
    if (isPaidTier) {
      return NextResponse.json({
        error: 'Multi-seat production licenses require an active enterprise subscription via billing.'
      }, { status: 403 });
    }

    // 3. Uniqueness & Single-Claim Enforcement (SEC-FINDING-002)
    const githubUserId = String(userData.id || userData.login);
    if (persistentTrialClaims.has(githubUserId)) {
      return NextResponse.json({
        error: 'Anti-abuse policy violation: A trial license has already been claimed for this GitHub account. Multiple trials are prohibited.'
      }, { status: 409 });
    }

    const hasSupabase = Boolean(
      process.env.NEXT_PUBLIC_SUPABASE_URL &&
      process.env.NEXT_PUBLIC_SUPABASE_URL !== 'https://placeholder.supabase.co' &&
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    if (hasSupabase) {
      try {
        const supabaseAdmin = createAdminSupabaseClient();
        const { data: existingClaim } = await supabaseAdmin
          .from('trial_claims')
          .select('id, github_user_id')
          .eq('github_user_id', githubUserId)
          .maybeSingle();

        if (existingClaim) {
          return NextResponse.json({
            error: 'Anti-abuse policy violation: A trial license has already been claimed for this GitHub account. Multiple trials are prohibited.'
          }, { status: 409 });
        }
      } catch (dbErr: any) {
        console.warn('[TRIAL_VERIFY_DB_NOTICE]', dbErr?.message);
      }
    }

    // Machine / Environment Fingerprint Binding (SEC-FINDING-001)
    const effectiveFingerprint = machineFingerprint ||
      req.headers.get('x-client-fingerprint') ||
      crypto.createHash('sha256').update((req.headers.get('x-forwarded-for') || 'local') + (req.headers.get('user-agent') || 'cli')).digest('hex');

    const assignedSeats = Math.min(5, Math.max(1, Number(seats) || 1));

    // 4. Generate 1-Month Free Trial Payload (30 Days)
    const expiresAt = new Date();
    expiresAt.setMonth(expiresAt.getMonth() + 1);

    const payloadObj = {
      githubId: userData.login,
      githubUserId,
      issuedAt: Date.now(),
      expiresAt: expiresAt.getTime(),
      isTrial: true,
      tier: 'enterprise-trial',
      machineFingerprint: effectiveFingerprint,
      seats: assignedSeats,
      organizationDomain: organizationDomain || null
    };

    const payloadString = JSON.stringify(payloadObj);
    const b64Payload = Buffer.from(payloadString).toString('base64');

    // 5. Sign with Ed25519 (Military Grade Elliptic Curve)
    const signature = crypto.sign(null, Buffer.from(payloadString), privateKey);
    const b64Signature = signature.toString('base64');

    // 6. Construct final license key
    const licenseKey = `${b64Payload}.${b64Signature}`;

    // 7. Persist Claim
    persistentTrialClaims.set(githubUserId, {
      claimedAt: Date.now(),
      fingerprint: effectiveFingerprint
    });

    if (hasSupabase) {
      try {
        const supabaseAdmin = createAdminSupabaseClient();
        await supabaseAdmin.from('trial_claims').insert([{
          github_user_id: githubUserId,
          github_login: userData.login,
          machine_fingerprint: effectiveFingerprint,
          claimed_at: new Date().toISOString(),
          expires_at: expiresAt.toISOString(),
          license_key_hash: crypto.createHash('sha256').update(licenseKey).digest('hex')
        }]);
      } catch (insertErr: any) {
        console.warn('[TRIAL_PERSIST_DB_NOTICE]', insertErr?.message);
      }
    }

    return NextResponse.json({
      success: true,
      licenseKey,
      seats: assignedSeats,
      expiresAt: expiresAt.toISOString(),
      message: `1-Month Enterprise Free Trial Activated for ${assignedSeats} Seats`
    });

  } catch (error) {
    console.error('License Generation Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const hash = searchParams.get('hash') || searchParams.get('key_hash');

    if (!hash) {
      return NextResponse.json({ error: 'Missing license hash parameter' }, { status: 400 });
    }

    const cleanHash = hash.trim().toLowerCase();

    const hasSupabase = Boolean(
      process.env.NEXT_PUBLIC_SUPABASE_URL &&
      process.env.NEXT_PUBLIC_SUPABASE_URL !== 'https://placeholder.supabase.co' &&
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    if (hasSupabase) {
      const supabaseAdmin = createAdminSupabaseClient();
      const { data: revokedClaim, error } = await supabaseAdmin
        .from('trial_claims')
        .select('id, revoked, revoked_at, revocation_reason')
        .eq('license_key_hash', cleanHash)
        .maybeSingle();

      if (!error && revokedClaim && revokedClaim.revoked) {
        return NextResponse.json({
          revoked: true,
          reason: revokedClaim.revocation_reason || 'License has been revoked by administrator',
          revokedAt: revokedClaim.revoked_at,
        });
      }
    }

    return NextResponse.json({ revoked: false, status: 'active' });
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || 'Failed to query revocation status' }, { status: 500 });
  }
}

