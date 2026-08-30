#!/usr/bin/env node
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const msg = JSON.parse(trimmed);
    const { id, method, params } = msg;

    if (method === 'initialize') {
      const response = {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'mock-mcp-server', version: '1.0.0' }
        }
      };
      process.stdout.write(JSON.stringify(response) + '\n');
      return;
    }

    if (method === 'notifications/initialized') {
      return; // Notification, no response
    }

    if (method === 'tools/list') {
      const response = {
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            { name: 'echo_tool', description: 'Echoes message' },
            { name: 'execute_cmd', description: 'Shell execution' },
            { name: 'fetch_data', description: 'Network fetch' },
            { name: 'leak_credentials', description: 'Returns raw secrets' },
            { name: 'inspect_args', description: 'Inspects received arguments' },
            { name: 'crash_server', description: 'Abruptly terminates' }
          ]
        }
      };
      process.stdout.write(JSON.stringify(response) + '\n');
      return;
    }

    if (method === 'call_tool') {
      const toolName = params?.name;
      const args = params?.arguments || {};

      if (toolName === 'echo_tool') {
        const response = {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `echo: ${args.message || ''}` }]
          }
        };
        process.stdout.write(JSON.stringify(response) + '\n');
        return;
      }

      if (toolName === 'leak_credentials') {
        const response = {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{
              type: 'text',
              text: 'Found keys: AKIAIOSFODNN7EXAMPLE and sk-proj-1234567890abcdef1234567890abcdef1234567890'
            }]
          }
        };
        process.stdout.write(JSON.stringify(response) + '\n');
        return;
      }

      if (toolName === 'inspect_args') {
        const response = {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{
              type: 'text',
              text: `received_auth: ${args.auth || ''}`
            }]
          }
        };
        process.stdout.write(JSON.stringify(response) + '\n');
        return;
      }

      if (toolName === 'crash_server') {
        process.exit(42);
      }

      // Default tool response
      const response = {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: `executed ${toolName}` }]
        }
      };
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  } catch (err) {
    // Malformed JSON received by mock server
  }
});
