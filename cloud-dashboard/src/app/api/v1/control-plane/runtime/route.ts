import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { supabase as adminSupabase } from '@/lib/supabase';
import { getAuthenticatedUserWithBearer } from '@/lib/authz';

export const runtime = 'nodejs';

interface AgentRuntimeSession {
  sessionId: string;
  agentType: 'mcp' | 'coding_agent' | 'browser_agent' | 'multi_agent';
  agentName: string;
  status: 'ACTIVE' | 'ISOLATED' | 'COMPLETED' | 'TERMINATED';
  delegationDepth: number;
  threatsNeutralized: number;
  lastAction: string;
  startedAt: string;
}

export async function GET(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { user, error: authError } = await getAuthenticatedUserWithBearer(req, supabase, adminSupabase);

    if (!user || authError) {
      return NextResponse.json({ error: 'Unauthorized: Authentication required' }, { status: 401 });
    }

    // Resolve user's organizations
    const { data: orgMemberships } = await adminSupabase
      .from('organization_members')
      .select('organization_id')
      .eq('user_id', user.id);

    const orgIds = (orgMemberships || []).map((m: any) => m.organization_id);
    let projectIds: string[] = [];

    if (orgIds.length > 0) {
      const { data: projects } = await adminSupabase
        .from('projects')
        .select('id')
        .in('organization_id', orgIds);
      projectIds = (projects || []).map((p: any) => p.id);
    }

    let sessions: AgentRuntimeSession[] = [];
    let totalThreats = 0;

    if (projectIds.length > 0) {
      // Query recent security events for the tenant's projects
      const { data: recentEvents } = await adminSupabase
        .from('security_events')
        .select('session_id, tool_name, event_type, risk_level, reason, created_at')
        .in('project_id', projectIds)
        .order('created_at', { ascending: false })
        .limit(100);

      if (recentEvents && recentEvents.length > 0) {
        const sessionMap = new Map<string, AgentRuntimeSession>();

        for (const ev of recentEvents) {
          const sid = ev.session_id || 'default-session';
          const isThreat = ev.event_type === 'BLOCK' || ev.event_type === 'QUARANTINE' || ev.risk_level === 'CRITICAL' || ev.risk_level === 'HIGH';

          if (!sessionMap.has(sid)) {
            sessionMap.set(sid, {
              sessionId: sid,
              agentType: 'mcp',
              agentName: `MCP Agent (${sid.slice(0, 8)})`,
              status: 'ACTIVE',
              delegationDepth: 1,
              threatsNeutralized: isThreat ? 1 : 0,
              lastAction: `${ev.event_type || 'PASSTHROUGH'}: ${ev.tool_name || 'agent'} - ${ev.reason || 'Monitored'}`,
              startedAt: ev.created_at,
            });
          } else {
            const existing = sessionMap.get(sid)!;
            if (isThreat) {
              existing.threatsNeutralized += 1;
            }
          }
        }

        sessions = Array.from(sessionMap.values());
        totalThreats = sessions.reduce((acc, s) => acc + s.threatsNeutralized, 0);
      }
    }

    return NextResponse.json({
      success: true,
      platform: 'MCP-Shield AI Agent Runtime Security Platform',
      activeAgentsCount: sessions.length,
      sessions,
      totalThreatsNeutralizedAcrossAgents: totalThreats,
      isLiveConnected: sessions.length > 0,
      isDemo: false,
      source: 'security_events',
      statusMessage: sessions.length > 0
        ? `${sessions.length} active agent sessions connected.`
        : 'No active agent sessions detected. Connect your MCP Shield Gateway to start streaming live telemetry.',
      supportedRuntimes: [
        'Model Context Protocol (MCP) Servers',
        'Coding Agents (Cursor, Cline, Aider, Claude Code)',
        'Browser Agents (Playwright, Puppeteer, Chrome DevTools)',
        'Multi-Agent Systems (LangGraph, AutoGen, CrewAI)',
      ],
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || 'Failed to query runtime telemetry' },
      { status: 500 }
    );
  }
}

