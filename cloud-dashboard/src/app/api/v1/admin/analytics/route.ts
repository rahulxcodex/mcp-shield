import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    // Verify master admin privilege
    const email = (user?.email || '').toLowerCase();
    const username = (user?.user_metadata?.user_name || '').toLowerCase();
    const isMaster =
      email === 'rahulsahygupta24@gmail.com' ||
      username === 'rahulxcodex';

    if (!user || !isMaster) {
      return NextResponse.json({ error: 'Forbidden: Master admin access required' }, { status: 403 });
    }

    // Mock/aggregate telemetry for master analytics
    const analyticsPayload = {
      timestamp: new Date().toISOString(),
      overview: {
        totalEvents24h: 384912,
        activeInstallations: 86,
        totalOrganizations: 14,
        avgLatencyMs: 0.42,
        systemHealth: 99.98,
      },
      sources: {
        mcp: {
          label: 'MCP Runtime Core',
          invocations24h: 312890,
          threatsBlocked: 4120,
          secretsSanitized: 12840,
          astInspectTimeAvg: '0.38ms',
          topToolsProtected: [
            { tool: 'execute_command', blocks: 1940, requests: 84200 },
            { tool: 'write_file', blocks: 1120, requests: 62400 },
            { tool: 'fetch_url', blocks: 820, requests: 43100 },
            { tool: 'eval_python', blocks: 240, requests: 12000 },
          ],
        },
        dashboard: {
          label: 'Cloud Dashboard Console',
          dailyActiveUsers: 142,
          activeSessionsNow: 18,
          keysGenerated24h: 24,
          soc2Exports24h: 38,
          attackSimulationsRun: 412,
        },
        website: {
          label: 'Marketing Website & Docs',
          uniqueVisitors24h: 3820,
          pageviews24h: 14890,
          conversionRatePct: 4.8,
          cliCopyCommands: 890,
          npmPackageViews: 12400,
        },
      },
      timeseries: [
        { time: '00:00', mcpEvents: 14200, dashboardActions: 62, webVisitors: 140 },
        { time: '04:00', mcpEvents: 8900, dashboardActions: 24, webVisitors: 90 },
        { time: '08:00', mcpEvents: 26400, dashboardActions: 180, webVisitors: 410 },
        { time: '12:00', mcpEvents: 42100, dashboardActions: 310, webVisitors: 680 },
        { time: '16:00', mcpEvents: 51200, dashboardActions: 290, webVisitors: 720 },
        { time: '20:00', mcpEvents: 34800, dashboardActions: 140, webVisitors: 390 },
      ],
      recentSystemEvents: [
        {
          id: 'ev-1',
          source: 'mcp',
          severity: 'HIGH',
          description: 'AST Command Injection Blocked on agent workstation',
          actor: 'Cursor Agent (acme-corp)',
          timestamp: '2 mins ago',
        },
        {
          id: 'ev-2',
          source: 'dashboard',
          severity: 'INFO',
          description: 'Enterprise invitation batch of 25 seats issued',
          actor: 'admin@fintech-security.io',
          timestamp: '14 mins ago',
        },
        {
          id: 'ev-3',
          source: 'website',
          severity: 'INFO',
          description: 'SOC 2 Type II audit report downloaded',
          actor: 'compliance-auditor@enterprise.com',
          timestamp: '32 mins ago',
        },
        {
          id: 'ev-4',
          source: 'mcp',
          severity: 'MEDIUM',
          description: 'Bijective DLP redacted AWS_SECRET_ACCESS_KEY from tool response',
          actor: 'Antigravity CLI (dev-cluster-9)',
          timestamp: '1 hour ago',
        },
      ],
    };

    return NextResponse.json({
      success: true,
      isMaster,
      data: analyticsPayload,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || 'Analytics query failure' },
      { status: 500 }
    );
  }
}
