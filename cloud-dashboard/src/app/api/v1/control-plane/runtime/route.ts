import { NextRequest, NextResponse } from 'next/server';

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

const RUNTIME_SESSIONS: AgentRuntimeSession[] = [
  {
    sessionId: 'sess-mcp-01',
    agentType: 'mcp',
    agentName: 'Claude Desktop MCP Gateway',
    status: 'ACTIVE',
    delegationDepth: 1,
    threatsNeutralized: 14,
    lastAction: 'tools/call:read_file (COW Sandbox Verified)',
    startedAt: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    sessionId: 'sess-code-02',
    agentType: 'coding_agent',
    agentName: 'Cursor Copilot Terminal Guard',
    status: 'ACTIVE',
    delegationDepth: 1,
    threatsNeutralized: 3,
    lastAction: 'terminal_exec:npm test (AST Verified)',
    startedAt: new Date(Date.now() - 1800000).toISOString(),
  },
  {
    sessionId: 'sess-browser-03',
    agentType: 'browser_agent',
    agentName: 'Playwright Autonomous Web Agent',
    status: 'ACTIVE',
    delegationDepth: 2,
    threatsNeutralized: 7,
    lastAction: 'navigate:docs.github.com (SSRF Blocked on 169.254.169.254)',
    startedAt: new Date(Date.now() - 900000).toISOString(),
  },
  {
    sessionId: 'sess-multi-04',
    agentType: 'multi_agent',
    agentName: 'LangGraph Multi-Agent Orchestrator',
    status: 'ACTIVE',
    delegationDepth: 3,
    threatsNeutralized: 5,
    lastAction: 'agent_handoff:researcher -> coder (Delegation Depth Guardrail)',
    startedAt: new Date(Date.now() - 450000).toISOString(),
  },
];

export async function GET() {
  return NextResponse.json({
    success: true,
    platform: 'MCP-Shield AI Agent Runtime Security Platform',
    stepLevel: 10,
    activeAgentsCount: RUNTIME_SESSIONS.length,
    sessions: RUNTIME_SESSIONS,
    totalThreatsNeutralizedAcrossAgents: RUNTIME_SESSIONS.reduce((acc, s) => acc + s.threatsNeutralized, 0),
    supportedRuntimes: [
      'Model Context Protocol (MCP) Servers',
      'Coding Agents (Cursor, Cline, Aider, Claude Code)',
      'Browser Agents (Playwright, Puppeteer, Chrome DevTools)',
      'Multi-Agent Systems (LangGraph, AutoGen, CrewAI)',
    ],
  });
}
