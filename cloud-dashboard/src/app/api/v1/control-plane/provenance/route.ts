import { NextRequest, NextResponse } from 'next/server';

interface ProvenanceRecord {
  serverId: string;
  publisher: string;
  verified: boolean;
  trustScore: number;
  toolCount: number;
  observedDeployments: number;
  activeDrift: boolean;
  lastFingerprint: string;
  lastAudited: string;
}

const KNOWN_SERVERS: ProvenanceRecord[] = [
  {
    serverId: 'filesystem-server',
    publisher: 'Anthropic Official',
    verified: true,
    trustScore: 98,
    toolCount: 8,
    observedDeployments: 14200,
    activeDrift: false,
    lastFingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    lastAudited: '2026-08-25',
  },
  {
    serverId: 'github-mcp-server',
    publisher: 'GitHub Verified',
    verified: true,
    trustScore: 96,
    toolCount: 24,
    observedDeployments: 9850,
    activeDrift: false,
    lastFingerprint: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
    lastAudited: '2026-08-28',
  },
  {
    serverId: 'postgres-mcp-server',
    publisher: 'Community Contributor',
    verified: true,
    trustScore: 88,
    toolCount: 12,
    observedDeployments: 3400,
    activeDrift: false,
    lastFingerprint: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    lastAudited: '2026-09-01',
  },
];

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const serverId = searchParams.get('serverId');

  if (serverId) {
    const record = KNOWN_SERVERS.find((s) => s.serverId.toLowerCase() === serverId.toLowerCase());
    if (!record) {
      return NextResponse.json({
        success: true,
        record: {
          serverId,
          publisher: 'Unverified / Unknown Publisher',
          verified: false,
          trustScore: 45,
          toolCount: 0,
          observedDeployments: 1,
          activeDrift: true,
          lastFingerprint: 'unregistered',
          lastAudited: 'never',
        },
      });
    }
    return NextResponse.json({ success: true, record });
  }

  return NextResponse.json({
    success: true,
    totalServersTracked: KNOWN_SERVERS.length,
    servers: KNOWN_SERVERS,
  });
}
