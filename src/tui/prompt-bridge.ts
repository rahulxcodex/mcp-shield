import React from 'react';
import * as fs from 'fs';

export interface PromptResult {
  action: 'approve' | 'reject' | 'timeout';
}

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
    try {
      const dynamicImport = new Function('specifier', 'return import(specifier)');
      const ink = await dynamicImport('ink');
      const { render, Box, Text, useInput } = ink;

      return new Promise((resolve) => {
        let isResolved = false;
        const ttyStdin = getTtyStdin();

        const PromptApp = () => {
          React.useEffect(() => {
            const timer = setTimeout(() => {
              handleResult({ action: 'timeout' });
            }, 60000);
            return () => clearTimeout(timer);
          }, []);

          useInput((input: string) => {
            if (input === 'y') handleResult({ action: 'approve' });
            if (input === 'n') handleResult({ action: 'reject' });
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
              React.createElement(Text, { bold: true }, '[y] Approve  [n] Reject (Timeout: 60s)')
            )
          );
        };

        const { unmount } = render(
          React.createElement(PromptApp),
          {
            stdout: process.stderr,
            stdin: ttyStdin as NodeJS.ReadStream,
          }
        );

        const handleResult = (result: PromptResult) => {
          if (!isResolved) {
            isResolved = true;
            unmount();
            resolve(result);
          }
        };
      });
    } catch (e) {
      return { action: 'reject' };
    }
  }
}
