import { NextResponse } from 'next/server';

export const runtime = 'edge';

export async function GET(request: Request) {
  // Dummy policy rules for initial implementation
  const dummyPolicies = {
    version: '1.0.0',
    rules: [
      {
        id: 'rule-1',
        action: 'BLOCK',
        condition: 'contains("rm -rf")',
        message: 'Destructive commands are not allowed.'
      },
      {
        id: 'rule-2',
        action: 'SANITIZE',
        condition: 'matches("([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+)")',
        message: 'Redacting email addresses.'
      },
      {
        id: 'rule-3',
        action: 'PROMPT',
        condition: 'tool_name == "sql_execute"',
        message: 'Sensitive database operation. Proceed?'
      }
    ]
  };

  return NextResponse.json(dummyPolicies);
}
