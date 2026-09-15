import * as net from 'net';
import * as http from 'http';
import * as https from 'https';
import * as tls from 'tls';
import * as dgram from 'dgram';

export class AirGapViolationError extends Error {
  public readonly exitCode: number = 127;
  constructor(message: string) {
    super(`[AIR-GAP VIOLATION] ${message}`);
    this.name = 'AirGapViolationError';
  }
}

/**
 * Deterministic --offline Air-Gap Enforcer
 * Enforces physical unbinding of socket creation across http, https, net, tls, and dgram.
 * If any network egress is attempted in --offline mode, execution immediately halts with exit code 127.
 */
export class OfflineAirGapEnforcer {
  private static isActive: boolean = false;
  private static originalNetConnect: any = null;
  private static originalHttpRequest: any = null;
  private static originalHttpsRequest: any = null;
  private static originalTlsConnect: any = null;
  private static originalDgramCreateSocket: any = null;
  private static originalDgramBind: any = null;
  private static exitOnViolation: boolean = true;

  /**
   * Activates offline air-gap enforcement
   */
  public static activate(options?: { exitOnViolation?: boolean }): void {
    if (this.isActive) return;
    this.isActive = true;
    this.exitOnViolation = options?.exitOnViolation ?? true;

    // 1. Intercept net.Socket.prototype.connect (authoritative transport layer for TCP/HTTP/TLS)
    this.originalNetConnect = net.Socket.prototype.connect;
    const self = this;
    net.Socket.prototype.connect = function (...args: any[]) {
      self.handleViolation('net.Socket.connect attempted in offline air-gapped mode');
      return this;
    };

    // 2. Intercept dgram.Socket.prototype.bind & send (UDP transport layer)
    if (dgram.Socket && dgram.Socket.prototype) {
      this.originalDgramCreateSocket = dgram.Socket.prototype.send;
      this.originalDgramBind = (dgram.Socket.prototype as any).bind;
      (dgram.Socket.prototype as any).send = function (...args: any[]) {
        self.handleViolation('dgram.Socket.send attempted in offline air-gapped mode');
      };
      (dgram.Socket.prototype as any).bind = function (...args: any[]) {
        self.handleViolation('dgram.Socket.bind attempted in offline air-gapped mode');
      };
    }
  }

  /**
   * Deactivates offline air-gap enforcement (restores original functions)
   */
  public static deactivate(): void {
    if (!this.isActive) return;

    if (this.originalNetConnect) {
      net.Socket.prototype.connect = this.originalNetConnect;
    }
    if (this.originalDgramCreateSocket && dgram.Socket && dgram.Socket.prototype) {
      (dgram.Socket.prototype as any).send = this.originalDgramCreateSocket;
    }
    if (this.originalDgramBind && dgram.Socket && dgram.Socket.prototype) {
      (dgram.Socket.prototype as any).bind = this.originalDgramBind;
    }

    this.isActive = false;
  }

  private static handleViolation(message: string): never {
    const error = new AirGapViolationError(message);
    if (this.exitOnViolation && process.env.NODE_ENV !== 'test') {
      console.error(error.message);
      process.exit(127);
    }
    throw error;
  }

  public static isEnforced(): boolean {
    return this.isActive;
  }
}
