import * as crypto from 'crypto';
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';

export interface TelemetryConfig {
  enabled: boolean;
  cloudEndpoint?: string;
  apiKey?: string;
  batchIntervalMs?: number;
  maxBatchSize?: number;
}

export interface SecurityTelemetryPayload {
  sessionId: string;
  eventType: 'BLOCK' | 'SANITIZE' | 'QUARANTINE' | 'RATE_LIMIT' | 'PROMPT' | 'PASSTHROUGH';
  detector: string;
  riskLevel: 'BENIGN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  toolName: string;
  reason: string;
  sanitizedPreview?: any;
  clientTimestamp: string;
}

export class CloudTelemetryPublisher {
  private queue: SecurityTelemetryPayload[] = [];
  private timer: NodeJS.Timeout | null = null;
  private config: TelemetryConfig;
  private configPath: string;

  constructor(config?: Partial<TelemetryConfig>) {
    this.configPath = path.resolve(os.homedir(), '.mcp-shield', 'cloud.json');
    const storedConfig = this.loadStoredConfig();

    this.config = {
      enabled: config?.enabled ?? storedConfig.enabled ?? !!process.env.MCP_SHIELD_API_KEY,
      cloudEndpoint: config?.cloudEndpoint || process.env.MCP_SHIELD_CLOUD_URL || storedConfig.cloudEndpoint || 'https://api.mcpshield.dev/v1/telemetry',
      apiKey: config?.apiKey || process.env.MCP_SHIELD_API_KEY || storedConfig.apiKey,
      batchIntervalMs: config?.batchIntervalMs || 5000,
      maxBatchSize: config?.maxBatchSize || 50
    };

    if (this.config.enabled && this.config.apiKey) {
      this.startBatchTimer();
    }
  }

  private loadStoredConfig(): Partial<TelemetryConfig> {
    try {
      if (fs.existsSync(this.configPath)) {
        return JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
      }
    } catch {}
    return {};
  }

  public saveConfig(config: Partial<TelemetryConfig>): void {
    try {
      const dir = path.dirname(this.configPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const merged = { ...this.loadStoredConfig(), ...config };
      fs.writeFileSync(this.configPath, JSON.stringify(merged, null, 2), 'utf8');
      this.config = { ...this.config, ...merged };
      if (this.config.enabled && this.config.apiKey && !this.timer) {
        this.startBatchTimer();
      }
    } catch (err: any) {
      console.error('[MCP-SHIELD CLOUD] Failed to persist cloud config:', err.message);
    }
  }

  public trackEvent(event: SecurityTelemetryPayload): void {
    if (!this.config.enabled || !this.config.apiKey) {
      return;
    }

    this.queue.push(event);
    if (this.queue.length >= (this.config.maxBatchSize || 50)) {
      this.flush();
    }
  }

  public static signPayload(payload: string, apiKey: string, timestamp: number): string {
    return crypto.createHmac('sha256', apiKey).update(`${timestamp}:${payload}`).digest('hex');
  }

  public async flush(): Promise<boolean> {
    if (this.queue.length === 0 || !this.config.apiKey || !this.config.cloudEndpoint) {
      return true;
    }

    const batch = [...this.queue];
    this.queue = [];

    const timestamp = Date.now();
    const payloadStr = JSON.stringify({
      device: {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch()
      },
      events: batch
    });

    const signature = CloudTelemetryPublisher.signPayload(payloadStr, this.config.apiKey, timestamp);

    try {
      if (typeof fetch !== 'undefined') {
        const res = await fetch(this.config.cloudEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-MCP-Shield-Key': this.config.apiKey.substring(0, 12),
            'X-MCP-Shield-Timestamp': String(timestamp),
            'X-MCP-Shield-Signature': signature
          },
          body: payloadStr
        });
        return res.ok;
      }
    } catch {
      // Re-queue events on network failure (fallback buffer)
      this.queue.unshift(...batch.slice(0, 100));
      return false;
    }

    return true;
  }

  private startBatchTimer(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.config.batchIntervalMs || 5000);
    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
