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
  eventId?: string;
  sequenceNumber?: number;
  sessionId: string;
  eventType: 'BLOCK' | 'SANITIZE' | 'QUARANTINE' | 'RATE_LIMIT' | 'PROMPT' | 'PASSTHROUGH' | 'ERROR';
  detector: string;
  riskLevel: 'BENIGN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  toolName: string;
  reason: string;
  sanitizedPreview?: any;
  clientTimestamp: string;
  installationId?: string;
  environment?: string;
  clientName?: string;
  serverName?: string;
}

export interface TelemetryDeliveryState {
  enabled: boolean;
  cloudEndpoint: string;
  hasApiKey: boolean;
  lastFlushSuccess: boolean;
  lastFlushTimestamp: number;
  lastError?: string;
  queuedCount: number;
  spooledCount: number;
  droppedCount: number;
}

export class CloudTelemetryPublisher {
  private queue: SecurityTelemetryPayload[] = [];
  private timer: NodeJS.Timeout | null = null;
  private config: TelemetryConfig;
  private configPath: string;
  private spoolPath: string;
  private installationId: string;
  private sequenceCounter = 0;
  private droppedEventsCount = 0;
  private isShuttingDown = false;
  private lastFlushSuccess = true;
  private lastFlushTimestamp = 0;
  private lastError: string | undefined = undefined;

  constructor(config?: Partial<TelemetryConfig>) {
    const baseDir = path.resolve(os.homedir(), '.mcp-shield');
    this.configPath = path.resolve(baseDir, 'cloud.json');
    this.spoolPath = path.resolve(baseDir, 'spool', 'telemetry.json');
    this.installationId = this.loadOrCreateInstallationId(baseDir);
    const storedConfig = this.loadStoredConfig();

    this.config = {
      enabled: config?.enabled ?? storedConfig.enabled ?? !!process.env.MCP_SHIELD_API_KEY,
      cloudEndpoint: config?.cloudEndpoint || process.env.MCP_SHIELD_CLOUD_URL || storedConfig.cloudEndpoint || 'https://cloud.mcp-shield.com/api/v1/telemetry/ingest',
      apiKey: config?.apiKey || process.env.MCP_SHIELD_API_KEY || storedConfig.apiKey,
      batchIntervalMs: config?.batchIntervalMs || 5000,
      maxBatchSize: config?.maxBatchSize || 50
    };

    this.recoverSpool();
    this.registerShutdownHooks();

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

  private loadOrCreateInstallationId(baseDir: string): string {
    try {
      if (!fs.existsSync(baseDir)) {
        fs.mkdirSync(baseDir, { recursive: true });
      }
      const idFile = path.resolve(baseDir, 'installation_id');
      if (fs.existsSync(idFile)) {
        const id = fs.readFileSync(idFile, 'utf8').trim();
        if (id) return id;
      }
      const newId = `inst_${crypto.randomBytes(8).toString('hex')}`;
      fs.writeFileSync(idFile, newId, 'utf8');
      return newId;
    } catch {
      return `inst_ephemeral_${crypto.randomBytes(4).toString('hex')}`;
    }
  }

  public getInstallationId(): string {
    return this.installationId;
  }

  public trackEvent(event: SecurityTelemetryPayload): void {
    if (!this.config.enabled || !this.config.apiKey) {
      return;
    }

    this.sequenceCounter += 1;
    const sanitizedEvent: SecurityTelemetryPayload = {
      ...event,
      eventId: event.eventId || `evt_${this.installationId}_${Date.now()}_${this.sequenceCounter}`,
      sequenceNumber: event.sequenceNumber ?? this.sequenceCounter,
      installationId: this.installationId,
      environment: event.environment || process.env.MCP_SHIELD_ENV || 'production',
      toolName: CloudTelemetryPublisher.redactSensitiveData(event.toolName || 'unknown'),
      reason: CloudTelemetryPublisher.redactSensitiveData(event.reason || 'Security policy evaluation'),
      sanitizedPreview: event.sanitizedPreview ? CloudTelemetryPublisher.sanitizePreviewPayload(event.sanitizedPreview) : undefined
    };

    this.queue.push(sanitizedEvent);
    if (this.queue.length >= (this.config.maxBatchSize || 50)) {
      this.flush().catch(() => {});
    }
  }

  public static redactSensitiveData(input: string): string {
    if (!input || typeof input !== 'string') return input;
    let text = input;
    // Redact Bearer / API keys
    text = text.replace(/([A-Za-z0-9_-]{20,})/g, (match) => {
      if (match.startsWith('mcp_live_') || match.startsWith('sk-') || match.startsWith('ghp_') || match.length >= 32) {
        return match.substring(0, 8) + '...[REDACTED]';
      }
      return match;
    });
    // Redact absolute local user directories
    text = text.replace(/(?:\/Users\/|[a-zA-Z]:\\Users\\)[^\\/\s"']+/g, '<USER_DIR>');
    return text;
  }

  public static sanitizePreviewPayload(payload: any): any {
    try {
      if (payload === null || payload === undefined) return undefined;
      
      const scrubObject = (obj: any, depth = 0): any => {
        if (depth > 4) return '[MAX_DEPTH]';
        if (obj === null || obj === undefined) return obj;
        if (typeof obj !== 'object') {
          if (typeof obj === 'string') {
            const redacted = CloudTelemetryPublisher.redactSensitiveData(obj);
            return redacted.length > 256 ? redacted.substring(0, 256) + '...[TRUNCATED]' : redacted;
          }
          return obj;
        }

        if (Array.isArray(obj)) {
          return obj.slice(0, 10).map(item => scrubObject(item, depth + 1));
        }

        const cleanObj: Record<string, any> = {};
        const sensitiveKeyRegex = /(password|secret|token|auth|key|credential|bearer|session|cookie)/i;
        for (const [k, v] of Object.entries(obj)) {
          if (sensitiveKeyRegex.test(k)) {
            cleanObj[k] = '[REDACTED]';
          } else {
            cleanObj[k] = scrubObject(v, depth + 1);
          }
        }
        return cleanObj;
      };

      const cleaned = scrubObject(payload);
      let str = JSON.stringify(cleaned);
      if (str.length > 512) {
        str = str.substring(0, 512) + '...[TRUNCATED_SIZE]';
        return { preview: str, truncated: true };
      }
      return JSON.parse(str);
    } catch {
      return { sanitized: true, preview: '[REDACTED_PREVIEW]' };
    }
  }

  public static signPayload(payload: string, apiKey: string, timestamp: number): string {
    return crypto.createHmac('sha256', apiKey).update(`${timestamp}:${payload}`).digest('hex');
  }

  public static extractKeyPrefix(apiKey: string): string {
    if (!apiKey) return '';
    const trimmed = apiKey.trim();
    const match = trimmed.match(/^(mcp_live(?:_sec)?_[a-f0-9]{8})_[a-f0-9]{32}$/i);
    if (match) {
      return match[1];
    }
    const prefixMatch = trimmed.match(/^(mcp_live(?:_sec)?_[a-f0-9]{8})/i);
    if (prefixMatch) {
      return prefixMatch[1];
    }
    const parts = trimmed.split('_');
    if (trimmed.startsWith('mcp_live_') && !trimmed.startsWith('mcp_live_sec_') && parts.length >= 3) {
      return parts.slice(0, 3).join('_');
    }
    if (trimmed.startsWith('mcp_live_sec_') && parts.length >= 4) {
      return parts.slice(0, 4).join('_');
    }
    return trimmed.substring(0, Math.min(trimmed.length, 20));
  }

  private recoverSpool(): void {
    try {
      if (fs.existsSync(this.spoolPath)) {
        const data = fs.readFileSync(this.spoolPath, 'utf8');
        const spooled = JSON.parse(data);
        if (Array.isArray(spooled) && spooled.length > 0) {
          // Take at most 100 spooled events to prevent sudden huge bursts
          const toRecover = spooled.slice(-100);
          this.queue.push(...toRecover);
          const remaining = spooled.slice(0, -100);
          if (remaining.length > 0) {
            fs.writeFileSync(this.spoolPath, JSON.stringify(remaining), 'utf8');
          } else {
            fs.unlinkSync(this.spoolPath);
          }
        }
      }
    } catch {
      // Non-blocking spool recovery
    }
  }

  private persistSpool(events: SecurityTelemetryPayload[]): void {
    try {
      const dir = path.dirname(this.spoolPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      let existing: SecurityTelemetryPayload[] = [];
      if (fs.existsSync(this.spoolPath)) {
        try {
          existing = JSON.parse(fs.readFileSync(this.spoolPath, 'utf8'));
        } catch {}
      }
      const combined = [...existing, ...events];
      const maxSpoolLimit = 5000;
      if (combined.length > maxSpoolLimit) {
        this.droppedEventsCount += combined.length - maxSpoolLimit;
        combined.splice(0, combined.length - maxSpoolLimit);
      }
      fs.writeFileSync(this.spoolPath, JSON.stringify(combined), 'utf8');
    } catch {
      // Non-blocking spool persistence
    }
  }

  public async flush(): Promise<boolean> {
    if (this.queue.length === 0 || !this.config.apiKey || !this.config.cloudEndpoint) {
      return true;
    }

    const batch = [...this.queue];
    this.queue = [];

    const timestamp = Date.now();
    const payloadStr = JSON.stringify({
      schemaVersion: 1,
      clientVersion: '1.0.12',
      eventVersion: 1,
      installation: {
        installationId: this.installationId,
        environment: process.env.MCP_SHIELD_ENV || 'production',
        droppedEvents: this.droppedEventsCount
      },
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
            'X-MCP-Shield-Key': this.config.apiKey,
            'X-MCP-Shield-Key-Prefix': CloudTelemetryPublisher.extractKeyPrefix(this.config.apiKey),
            'Authorization': `Bearer ${this.config.apiKey}`,
            'X-MCP-Shield-Timestamp': String(timestamp),
            'X-MCP-Shield-Signature': signature
          },
          body: payloadStr
        });
        if (res.ok) {
          this.lastFlushSuccess = true;
          this.lastFlushTimestamp = Date.now();
          this.lastError = undefined;
          return true;
        } else {
          this.lastError = `Cloud HTTP status ${res.status}: ${res.statusText}`;
        }
      }
    } catch (err: any) {
      this.lastError = err?.message || 'Network unreachable';
    }

    this.lastFlushSuccess = false;
    this.lastFlushTimestamp = Date.now();
    // Persist to local disk spool on failure
    this.persistSpool(batch);
    return false;
  }

  public getDeliveryState(): TelemetryDeliveryState {
    let spooledCount = 0;
    if (fs.existsSync(this.spoolPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(this.spoolPath, 'utf8'));
        if (Array.isArray(data)) spooledCount = data.length;
      } catch {}
    }
    return {
      enabled: this.config.enabled,
      cloudEndpoint: this.config.cloudEndpoint || '',
      hasApiKey: !!this.config.apiKey,
      lastFlushSuccess: this.lastFlushSuccess,
      lastFlushTimestamp: this.lastFlushTimestamp,
      lastError: this.lastError,
      queuedCount: this.queue.length,
      spooledCount,
      droppedCount: this.droppedEventsCount
    };
  }

  private registerShutdownHooks(): void {
    const handleExit = () => {
      if (this.isShuttingDown) return;
      this.isShuttingDown = true;
      this.stop();
      if (this.queue.length > 0) {
        this.persistSpool(this.queue);
        this.queue = [];
      }
    };

    process.once('beforeExit', handleExit);
    process.once('SIGINT', handleExit);
    process.once('SIGTERM', handleExit);
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
