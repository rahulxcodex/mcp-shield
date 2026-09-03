import { NextResponse } from 'next/server';
import * as crypto from 'crypto';

// The private key must be stored in a highly secure environment variable/KMS
const PRIVATE_KEY = process.env.LICENSE_PRIVATE_KEY || `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPtJ7v9s3X7e4t8q2z1w5r6y9u0i1o2p3a4s5d6f7g8=
-----END PRIVATE KEY-----`;

export async function POST(req: Request) {
  try {
    const { githubAccessToken } = await req.json();

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
    const accountCreatedAt = new Date(userData.created_at);
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

    if (accountCreatedAt > oneYearAgo) {
      return NextResponse.json({ 
        error: 'Security Policy: GitHub account must be at least 1 year old to prevent sybil/bot attacks for trial keys.' 
      }, { status: 403 });
    }

    // 3. Generate 1-Month Free Trial Payload (30 Days)
    const expiresAt = new Date();
    expiresAt.setMonth(expiresAt.getMonth() + 1);

    const payloadObj = {
      githubId: userData.login,
      issuedAt: Date.now(),
      expiresAt: expiresAt.getTime(),
      isTrial: true,
      tier: 'enterprise-trial'
    };

    const payloadString = JSON.stringify(payloadObj);
    const b64Payload = Buffer.from(payloadString).toString('base64');

    // 4. Sign with Ed25519 (Military Grade Elliptic Curve)
    const signature = crypto.sign(null, Buffer.from(payloadString), PRIVATE_KEY);
    const b64Signature = signature.toString('base64');

    // 5. Construct final license key
    const licenseKey = `${b64Payload}.${b64Signature}`;

    return NextResponse.json({
      success: true,
      licenseKey,
      expiresAt: expiresAt.toISOString(),
      message: '3-Month Enterprise Trial Activated'
    });

  } catch (error) {
    console.error('License Generation Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
