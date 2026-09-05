import { NextResponse } from 'next/server';

export async function GET() {
  const hasSupabase = !!(process.env.NEXT_PUBLIC_SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY));
  const hasLicenseKey = !!(process.env.LICENSE_PRIVATE_KEY || process.env.NEXT_PUBLIC_LICENSE_PUBLIC_KEY);
  const intelEndpoint = process.env.ENTERPRISE_INTEL_ENDPOINT || 'https://mcp-shield-enterprise-intel.onrender.com';

  const ready = hasSupabase;
  const status = ready ? 'ok' : 'degraded';

  return NextResponse.json(
    {
      status,
      ready,
      timestamp: new Date().toISOString(),
      service: 'mcp-shield-control-plane',
      checks: {
        database: hasSupabase ? 'available' : 'unconfigured',
        licenseService: hasLicenseKey ? 'configured' : 'degraded',
        intelEndpointConfigured: Boolean(intelEndpoint),
      },
    },
    { status: ready ? 200 : 503 }
  );
}
