import React, { useEffect } from 'react';
import { render, Box, Text, useInput } from 'ink';
import * as fs from 'fs';

export interface PromptResult {
  action: 'approve' | 'reject' | 'always_allow' | 'sandbox' | 'timeout';
}

interface PromptAppProps {
  title: string;
  message: string;
  riskLevel: string;
  diff?: string;
  onResult: (result: PromptResult) => void;
}

const PromptApp: React.FC<PromptAppProps> = ({ title, message, riskLevel, diff, onResult }) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      onResult({ action: 'timeout' });
    }, 60000);
    return () => clearTimeout(timer);
  }, [onResult]);

  useInput((input, key) => {
    if (input === 'y') onResult({ action: 'approve' });
    if (input === 'n') onResult({ action: 'reject' });
    if (input === 'a') onResult({ action: 'always_allow' });
    if (input === 's') onResult({ action: 'sandbox' });
  });

  const borderColor = riskLevel === 'CRITICAL' ? 'red' : 'yellow';

  return React.createElement(Box, { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor },
    React.createElement(Text, { bold: true, color: borderColor }, `${title} [${riskLevel}]`),
    React.createElement(Box, { marginY: 1 }, React.createElement(Text, null, message)),
    diff ? React.createElement(Box, { flexDirection: 'column', marginY: 1 },
      React.createElement(Text, { bold: true }, 'Diff:'),
      React.createElement(Text, null, diff)
    ) : null,
    React.createElement(Box, { marginTop: 1 },
      React.createElement(Text, { bold: true }, '[y] Approve  [n] Reject  [a] Always Allow  [s] Sandbox (Timeout: 60s)')
    )
  );
};

const getTtyStdin = () => {
  try {
    if (process.platform === 'win32') {
      const stream = fs.createReadStream('\\\\.\\CON');
      return stream;
    } else {
      const stream = fs.createReadStream('/dev/tty');
      return stream;
    }
  } catch (e) {
    return process.stdin;
  }
};

export class PromptBridge {
  public static async ask(title: string, message: string, riskLevel: string, diff?: string): Promise<PromptResult> {
    return new Promise((resolve) => {
      let isResolved = false;
      const ttyStdin = getTtyStdin();
      
      const { unmount } = render(
        React.createElement(PromptApp, {
          title,
          message,
          riskLevel,
          diff,
          onResult: (result: PromptResult) => {
            if (!isResolved) {
              isResolved = true;
              unmount();
              resolve(result);
            }
          }
        }),
        {
          stdout: process.stderr,
          stdin: ttyStdin as NodeJS.ReadStream,
        }
      );
    });
  }
}
