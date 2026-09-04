import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { supabase as adminSupabase } from '@/lib/supabase';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const filterType = searchParams.get('filter') || 'ALL';
    const querySearch = searchParams.get('query') || '';
    const limit = parseInt(searchParams.get('limit') || '50', 10);

    const hasSupabase = Boolean(
      process.env.NEXT_PUBLIC_SUPABASE_URL && 
      process.env.NEXT_PUBLIC_SUPABASE_URL !== 'https://placeholder.supabase.co'
    );

    if (hasSupabase) {
      try {
        const userClient = await createClient();
        const { data: { user } } = await userClient.auth.getUser();

        if (!user) {
          return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
        }

        const { data: orgs } = await adminSupabase
          .from('organization_members')
          .select('organization_id')
          .eq('user_id', user.id);
        const orgIds = (orgs || []).map((o: any) => o.organization_id);

        if (orgIds.length === 0) {
          return NextResponse.json({ events: [], live: true });
        }

        const { data: projects } = await adminSupabase
          .from('projects')
          .select('id')
          .in('organization_id', orgIds);
        const projectIds = (projects || []).map((p: any) => p.id);

        if (projectIds.length === 0) {
          return NextResponse.json({ events: [], live: true });
        }

        let dbQuery = adminSupabase
          .from('security_events')
          .select('id, event_id, session_id, event_type, detector, risk_level, tool_name, reason, sanitized_preview, client_timestamp, created_at, sequence_number, installation_id, environment')
          .in('project_id', projectIds)
          .order('created_at', { ascending: false })
          .limit(limit);

        if (filterType !== 'ALL') {
          dbQuery = dbQuery.eq('event_type', filterType);
        }

        const { data: events, error } = await dbQuery;

        // Check active agent instances for genuine live connection status
        const sixtySecondsAgo = new Date(Date.now() - 60 * 1000).toISOString();
        const { data: activeAgents } = await adminSupabase
          .from('agent_instances')
          .select('id, last_heartbeat_at')
          .in('project_id', projectIds)
          .gte('last_heartbeat_at', sixtySecondsAgo)
          .limit(1);

        const isLiveConnected = Boolean(activeAgents && activeAgents.length > 0);

        if (!error && events && events.length > 0) {
          let filtered = events.map((e: any) => ({
            id: e.id,
            eventId: e.event_id || e.id,
            timestamp: formatTimeAgo(e.created_at || e.client_timestamp),
            eventType: e.event_type,
            toolName: e.tool_name,
            detector: e.detector,
            riskLevel: e.risk_level,
            reason: e.reason,
            sequenceNumber: e.sequence_number,
            installationId: e.installation_id,
            environment: e.environment || 'production',
            rawTimestamp: e.created_at || e.client_timestamp
          }));

          if (querySearch.trim()) {
            const q = querySearch.toLowerCase();
            filtered = filtered.filter((ev: any) =>
              ev.toolName.toLowerCase().includes(q) ||
              ev.reason.toLowerCase().includes(q) ||
              ev.detector.toLowerCase().includes(q)
            );
          }

          return NextResponse.json({ events: filtered, live: isLiveConnected, agentConnected: isLiveConnected });
        }

        // Authenticated user with zero events: return real empty events (NEVER fake demo data)
        return NextResponse.json({ events: [], live: isLiveConnected, agentConnected: isLiveConnected });
      } catch (err: any) {
        console.warn('[TELEMETRY_EVENTS] Database lookup warning:', err?.message);
        return NextResponse.json({ events: [], live: true });
      }
    }
  } catch (err: any) {
    console.error('[TELEMETRY_EVENTS] Route error:', err);
  }

  // Return genuine empty events array (never fake demo attacks)
  return NextResponse.json({
    events: [],
    live: false
  });
}

function formatTimeAgo(dateStr: string): string {
  try {
    const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  } catch {
    return 'Recently';
  }
}
