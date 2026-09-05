import { NextResponse } from 'next/server';
import crypto from 'crypto';

/**
 * Sanitizes errors returned to clients.
 * In production, suppresses internal database/provider stack traces and returns a clean error message with correlation ID.
 */
export function sanitizeApiError(
  error: unknown,
  fallbackMessage = 'Internal server error',
  statusCode = 500
): NextResponse {
  const correlationId = `err_${crypto.randomBytes(6).toString('hex')}`;
  const isProd = process.env.NODE_ENV === 'production';

  // Server-side audit logging
  console.error(`[API_ERROR] [Correlation: ${correlationId}]`, error);

  if (isProd) {
    return NextResponse.json(
      {
        error: fallbackMessage,
        correlationId,
      },
      { status: statusCode }
    );
  }

  // Development: include message for debugging
  const errorMessage = error instanceof Error ? error.message : String(error || fallbackMessage);
  return NextResponse.json(
    {
      error: errorMessage,
      correlationId,
    },
    { status: statusCode }
  );
}

export function jsonSuccess<T>(data: T, status = 200, headers: HeadersInit = {}): NextResponse {
  return NextResponse.json(data, { status, headers });
}

export function jsonError(message: string, status = 400, details?: unknown): NextResponse {
  return NextResponse.json({ error: message, ...(details ? { details } : {}) }, { status });
}

