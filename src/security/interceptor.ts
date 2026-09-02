export interface ToolPayload {
  toolName: string;
  parameters: Record<string, any>;
}

export class InterceptorLayer {
  // Simple regex for SSN and MRN (Medical Record Number) patterns
  private piiRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
  private phiRegex = /\bMRN-\d{7,10}\b/g;

  /**
   * Scans payloads for PII/PHI and applies context-aware pseudonymization
   */
  public redactPayload(payload: string): string {
    let redacted = payload.replace(this.piiRegex, '[REDACTED_SSN]');
    redacted = redacted.replace(this.phiRegex, '[REDACTED_MRN]');
    return redacted;
  }

  /**
   * Enforces deterministic parameter clamping for industrial/OT safety
   */
  public clampParameters(payload: ToolPayload): ToolPayload {
    if (payload.toolName === 'set_turbine_speed') {
      const speed = payload.parameters.rpm;
      if (typeof speed === 'number') {
        // Hard physical safety interlock: cap at 3000 RPM
        payload.parameters.rpm = Math.min(speed, 3000);
      }
    }
    return payload;
  }
}
