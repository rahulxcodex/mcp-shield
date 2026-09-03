import { NextRequest, NextResponse } from 'next/server';

interface EnterprisePolicyRule {
  id: string;
  name: string;
  category: 'NETWORK' | 'SHELL' | 'FILESYSTEM' | 'DLP' | 'RUNTIME';
  effect: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE';
  condition: string;
  version: number;
  inheritedFrom?: string;
  environment: 'production' | 'staging' | 'development';
}

const DEFAULT_ENTERPRISE_POLICIES: EnterprisePolicyRule[] = [
  {
    id: 'POL-NET-001',
    name: 'Zero-Trust SSRF & Link-Local Quarantine',
    category: 'NETWORK',
    effect: 'BLOCK',
    condition: 'destination in [169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]',
    version: 3,
    environment: 'production',
  },
  {
    id: 'POL-DLP-002',
    name: 'Bijective FPE Secret Tokenization',
    category: 'DLP',
    effect: 'SANITIZE',
    condition: 'payload.matches(AWS_KEY | GITHUB_PAT | RSA_PRIVATE_KEY)',
    version: 4,
    environment: 'production',
  },
  {
    id: 'POL-SHELL-003',
    name: 'Subshell AST Chaining & Fork Bomb Prevention',
    category: 'SHELL',
    effect: 'BLOCK',
    condition: 'ast.contains(CommandSubstitution | PipeInterpreter | ForkBomb)',
    version: 2,
    environment: 'production',
  },
  {
    id: 'POL-RUNTIME-004',
    name: 'Multi-Agent Delegation Depth Cap (Depth <= 5)',
    category: 'RUNTIME',
    effect: 'QUARANTINE',
    condition: 'agent.delegation_depth > 5',
    version: 1,
    environment: 'production',
  },
];

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const environment = searchParams.get('env') || 'production';
  const category = searchParams.get('category');

  let filtered = DEFAULT_ENTERPRISE_POLICIES.filter((p) => p.environment === environment);
  if (category) {
    filtered = filtered.filter((p) => p.category.toLowerCase() === category.toLowerCase());
  }

  return NextResponse.json({
    success: true,
    environment,
    policiesCount: filtered.length,
    policies: filtered,
    syncedAt: new Date().toISOString(),
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    if (!body.name || !body.category || !body.effect) {
      return NextResponse.json({ error: 'Missing required fields: name, category, effect' }, { status: 400 });
    }

    const newRule: EnterprisePolicyRule = {
      id: `POL-CUSTOM-${Date.now().toString(36).toUpperCase()}`,
      name: body.name,
      category: body.category,
      effect: body.effect,
      condition: body.condition || 'custom_expression',
      version: 1,
      environment: body.environment || 'production',
    };

    DEFAULT_ENTERPRISE_POLICIES.unshift(newRule);

    return NextResponse.json({
      success: true,
      message: 'Enterprise policy rule committed successfully',
      rule: newRule,
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: 'Invalid policy JSON payload' }, { status: 400 });
  }
}
