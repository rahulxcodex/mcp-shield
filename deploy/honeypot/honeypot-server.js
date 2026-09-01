/**
 * MCP Shield Honeypot & Canary Decoy Server
 *
 * Implements auditor recommendation #4: Canary endpoints and decoy tools.
 * Exposes fake high-privilege tools (e.g. AWS IAM escalation, database root dump,
 * debug shell) to trap prompt-injected or hallucinating AI agents before they can
 * reach legitimate production infrastructure.
 */

const http = require('http');

const PORT = process.env.HONEYPOT_PORT || 9090;

const DECOY_TOOLS = [
  {
    name: 'aws_escalate_admin_iam',
    description: 'Internal AWS administrative privilege escalation tool. Grants AdministratorAccess role.',
    parameters: {
      type: 'object',
      properties: {
        targetRoleArn: { type: 'string', description: 'Target IAM Role ARN' },
        temporaryDurationSeconds: { type: 'number', description: 'Duration for elevated token' }
      },
      required: ['targetRoleArn']
    }
  },
  {
    name: 'database_dump_all_credentials',
    description: 'Administrative database utility to export all master credentials, connection strings, and tokens.',
    parameters: {
      type: 'object',
      properties: {
        clusterEndpoint: { type: 'string', description: 'RDS or PostgreSQL cluster host' },
        includeMasterKey: { type: 'boolean', description: 'Whether to include root encryption keys' }
      },
      required: ['clusterEndpoint']
    }
  },
  {
    name: 'host_root_debug_shell',
    description: 'Internal hypervisor debug backdoor. Executes commands as root on the host node.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Raw shell command to execute as root' }
      },
      required: ['command']
    }
  }
];

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    try {
      const payload = body ? JSON.parse(body) : {};

      // 1. Tool Listing Request
      if (payload.method === 'tools/list') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          jsonrpc: '2.0',
          result: { tools: DECOY_TOOLS },
          id: payload.id || null
        }));
      }

      // 2. Honeypot Tool Invocation Trap!
      if (payload.method === 'tools/call') {
        const toolName = payload.params?.name;
        const invocationArgs = payload.params?.arguments;

        console.error(`🚨 [HONEYPOT TRAP TRIGGERED] Agent attempted unauthorized call to Canary Tool: ${toolName}`);
        console.error(`🚨 Details: ${JSON.stringify(invocationArgs)}`);

        // Return a mock failure that signals MCP Shield security monitoring
        res.writeHead(403, {
          'Content-Type': 'application/json',
          'X-MCP-Shield-Tripwire': 'HONEYPOT_ACTIVATED',
          'X-MCP-Shield-Severity': 'CRITICAL'
        });
        return res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: {
            code: -32001,
            message: 'Tripwire Alert: Unauthorized access to Canary Honeypot Endpoint. Event logged and session quarantined.',
            data: {
              tripwire: 'CANARY_HONEYPOT_HIT',
              toolName,
              timestamp: new Date().toISOString()
            }
          },
          id: payload.id || null
        }));
      }

      // Default Health Endpoint
      if (req.url === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('OK');
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found' }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Honeypot Error' }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`🛡️  MCP Shield Honeypot & Canary Decoy Server listening on port ${PORT}`);
});
