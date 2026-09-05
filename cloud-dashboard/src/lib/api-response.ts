import { NextResponse } from 'next/server';

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    requestId?: string;
    details?: string[];
  };
}

export function jsonSuccess<T>(data: T, status = 200, customHeaders?: Record<string, string>): NextResponse {
  const response = NextResponse.json(data, { status });
  applySecurityHeaders(response);
  if (customHeaders) {
    for (const [key, val] of Object.entries(customHeaders)) {
      response.headers.set(key, val);
    }
  }
  return response;
}

export function jsonError(
  code: string,
  message: string,
  status = 400,
  requestId?: string,
  details?: string[]
): NextResponse {
  const payload: ApiErrorResponse = {
    error: {
      code,
      message,
      requestId,
      details,
    },
  };
  const response = NextResponse.json(payload, { status });
  applySecurityHeaders(response);
  return response;
}

export function applySecurityHeaders(response: NextResponse): void {
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
}
