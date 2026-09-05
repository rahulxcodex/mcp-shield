import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { createAdminSupabaseClient } from '@/lib/supabase';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    // Verify master admin privilege strictly via immutable server-managed app_metadata or configured admin ID
    const email = (user?.email || '').toLowerCase();
    const adminEmail = process.env.MASTER_ADMIN_EMAIL ? process.env.MASTER_ADMIN_EMAIL.toLowerCase() : null;
    const isMaster =
      (adminEmail && email === adminEmail) ||
      user?.app_metadata?.role === 'master_admin' ||
      (process.env.MASTER_ADMIN_USER_ID && user?.id === process.env.MASTER_ADMIN_USER_ID);

    if (!user || !isMaster) {
      return NextResponse.json({ error: 'Forbidden: Master admin access required' }, { status: 403 });
    }

    // Query real operational metrics from authoritative database using admin client
    // (Bypasses RLS to capture complete cross-tenant aggregates for master admin)
    const adminSupabase = createAdminSupabaseClient();
    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();

    const [
      { count: totalOrgs },
      { count: activeAgents },
      { count: events24h },
      { count: threatsBlocked24h },
      { data: recentEvents }
    ] = await Promise.all([
      adminSupabase.from('organizations').select('*', { count: 'exact', head: true }),
      adminSupabase.from('agent_instances').select('*', { count: 'exact', head: true }).eq('status', 'ONLINE'),
      adminSupabase.from('security_events').select('*', { count: 'exact', head: true }).gte('created_at', twentyFourHoursAgo),
      adminSupabase.from('security_events').select('*', { count: 'exact', head: true }).in('event_type', ['BLOCK', 'QUARANTINE']).gte('created_at', twentyFourHoursAgo),
      adminSupabase.from('security_events').select('id, event_type, risk_level, tool_name, reason, created_at').order('created_at', { ascending: false }).limit(10)
    ]);

    const analyticsPayload = {
      timestamp: now.toISOString(),
      isDemo: false,
      overview: {
        totalEvents24h: events24h || 0,
        activeInstallations: activeAgents || 0,
        totalOrganizations: totalOrgs || 0,
        threatsBlocked24h: threatsBlocked24h || 0,
        systemHealth: 100.0,
      },
      recentSystemEvents: (recentEvents || []).map((ev: any) => ({
        id: ev.id,
        source: 'mcp',
        severity: ev.risk_level || 'INFO',
        description: ev.reason || `${ev.event_type} on ${ev.tool_name}`,
        actor: ev.tool_name || 'agent',
        timestamp: ev.created_at,
      })),
    };

    return NextResponse.json({
      success: true,
      isMaster: true,
      data: analyticsPayload,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || 'Analytics query failure' },
      { status: 500 }
    );
  }
}
