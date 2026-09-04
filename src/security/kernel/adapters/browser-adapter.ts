/**
 * MCP Shield - Browser Protocol Adapter
 * Step 3 Roadmap - Section 18 & Milestone D
 *
 * Normalizes Browser automation agent actions (navigate, click, eval, cookies, localStorage, fetch)
 * into canonical Kernel requests.
 */

import { ProtocolAdapter, CanonicalKernelRequest } from '../agent-security-kernel';

export interface BrowserActionPayload {
  action: 'navigate' | 'click' | 'type' | 'evaluate' | 'getCookies' | 'fetch' | 'download';
  targetUrl?: string;
  selector?: string;
  script?: string;
  payload?: any;
}

export class BrowserProtocolAdapter implements ProtocolAdapter {
  public readonly protocol = 'browser';

  public normalize(rawAction: BrowserActionPayload): CanonicalKernelRequest {
    const candidateCommands: string[] = [];
    const candidateUrls: string[] = [];
    let destination: string | undefined;

    if (rawAction.script) {
      candidateCommands.push(rawAction.script);
    }
    if (rawAction.targetUrl) {
      candidateUrls.push(rawAction.targetUrl);
      try {
        destination = new URL(rawAction.targetUrl).hostname;
      } catch {
        destination = rawAction.targetUrl;
      }
    }

    return {
      protocol: 'browser',
      callerIdentity: 'browser-agent-runtime',
      actionName: `browser_${rawAction.action}`,
      parameters: {
        action: rawAction.action,
        selector: rawAction.selector,
        url: rawAction.targetUrl,
        payload: rawAction.payload
      },
      candidateCommands,
      candidatePaths: [],
      candidateUrls,
      destination,
      metadata: {
        browserEngine: 'playwright/puppeteer',
        capabilities: [
          rawAction.action === 'evaluate' ? 'shellExecution' : null,
          rawAction.targetUrl ? 'networkAccess' : null,
          rawAction.action === 'getCookies' ? 'secretAccess' : null
        ].filter(Boolean)
      }
    };
  }
}
