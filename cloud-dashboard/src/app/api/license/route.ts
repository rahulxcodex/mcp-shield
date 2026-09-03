import { NextResponse } from 'next/server';
import * as crypto from 'crypto';

const getPrivateKey = () => {
  const envKey = process.env.LICENSE_PRIVATE_KEY;
  if (!envKey) {
    throw new Error('LICENSE_PRIVATE_KEY is not configured on the server (fail-closed).');
  }
  return envKey.replace(/\\n/g, '\n').trim();
};

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const { githubAccessToken, seats = 5, tier = 'enterprise-trial', organizationDomain } = body;

    if (!githubAccessToken) {
      return NextResponse.json({ error: 'GitHub Token required' }, { status: 400 });
    }

    // 1. Authenticate with GitHub & enforce Anti-Sybil account age check
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
    if (!userData.created_at) {
      return NextResponse.json({ error: 'Unable to verify account creation date' }, { status: 400 });
    }

    const accountAge = Date.now() - new Date(userData.created_at).getTime();
    const oneYearMs = 365 * 24 * 60 * 60 * 1000;
    if (accountAge < oneYearMs) {
      return NextResponse.json({
        error: 'Anti-Sybil policy violation: GitHub account must be at least 1 year old.'
      }, { status: 403 });
    }

    // Unpaid public self-service requests are restricted strictly to enterprise-trial (max 5 seats)
    const isPaidTier = tier === 'enterprise' && Number(seats) > 5;
    if (isPaidTier) {
      return NextResponse.json({
        error: 'Multi-seat production licenses require an active enterprise subscription via billing.'
      }, { status: 403 });
    }

    const assignedSeats = Math.min(5, Math.max(1, Number(seats) || 1));

    // 2. Generate License Payload
    const expiresAt = new Date();
    expiresAt.setMonth(expiresAt.getMonth() + 1);

    const payloadObj = {
      githubId: userData.login,
      issuedAt: Date.now(),
      expiresAt: expiresAt.getTime(),
      isTrial: true,
      tier: 'enterprise-trial',
      seats: assignedSeats,
      organizationDomain: organizationDomain || null
    };

    const payloadString = JSON.stringify(payloadObj);
    const b64Payload = Buffer.from(payloadString).toString('base64');

    // 3. Sign with Ed25519 (fail-closed if server key not set)
    let privateKeyPem: string;
    try {
      privateKeyPem = getPrivateKey();
    } catch (keyErr: any) {
      console.error('[LICENSE_MINT_ERROR]', keyErr.message);
      return NextResponse.json({ error: 'License server signing key unavailable' }, { status: 500 });
    }

    const signature = crypto.sign(null, Buffer.from(payloadString), privateKeyPem);
    const b64Signature = signature.toString('base64');

    // 4. Construct final single enterprise trial license key
    const licenseKey = `${b64Payload}.${b64Signature}`;

    return NextResponse.json({
      success: true,
      licenseKey,
      seats: assignedSeats,
      expiresAt: expiresAt.toISOString(),
      message: `Enterprise Trial License Activated for ${assignedSeats} Seats`
    });

  } catch (error: any) {
    console.error('License Generation Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
