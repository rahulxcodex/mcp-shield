import { createServerClient, type CookieOptions } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

export async function middleware(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  })

  const pathname = request.nextUrl.pathname;
  const method = request.method;

  // CSRF & Origin Protection for mutating API requests (POST, PUT, PATCH, DELETE)
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && (pathname.startsWith('/api/v1/') || pathname.startsWith('/api/license'))) {
    // Exempt cryptographic webhook endpoints and HMAC-signed telemetry ingest
    const isExempt = pathname === '/api/v1/billing/webhook' || pathname === '/api/v1/telemetry/ingest';
    
    const authHeader = request.headers.get('authorization');
    const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7).trim() : undefined;

    if (!isExempt && !bearerToken) {
      const origin = request.headers.get('origin');
      const host = request.headers.get('host');
      const secFetchSite = request.headers.get('sec-fetch-site');

      if (secFetchSite === 'cross-site') {
        return NextResponse.json(
          { error: 'Forbidden: Cross-site request rejected (CSRF Protection)' },
          { status: 403 }
        );
      }

      if (origin && host) {
        try {
          const originHost = new URL(origin).host;
          if (originHost !== host) {
            return NextResponse.json(
              { error: 'Forbidden: Untrusted request origin (CSRF Protection)' },
              { status: 403 }
            );
          }
        } catch {
          return NextResponse.json({ error: 'Forbidden: Malformed origin' }, { status: 403 });
        }
      }
    }
  }

  // Always allow public routes
  if (
    pathname === '/' ||
    pathname === '/sitemap.xml' ||
    pathname === '/robots.txt' ||
    pathname.startsWith('/.well-known') ||
    pathname === '/terms' ||
    pathname === '/privacy' ||
    pathname === '/security' ||
    pathname === '/compliance' ||
    pathname === '/subprocessors' ||
    pathname.startsWith('/login') ||
    pathname.startsWith('/auth') ||
    pathname.startsWith('/guide') ||
    pathname.startsWith('/api/v1/telemetry') ||
    pathname === '/api/v1/support/complaint' ||
    pathname === '/api/license'
  ) {
    return supabaseResponse;
  }

  // In development, if Supabase is unconfigured, allow developer preview only if explicitly enabled
  const isProd = process.env.NODE_ENV === 'production';
  const allowDevBypass = process.env.ALLOW_DEV_AUTH_BYPASS === 'true';

  if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) {
    if (isProd || !allowDevBypass) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json({ error: 'Service Unavailable: Authentication infrastructure unconfigured' }, { status: 503 });
      }
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('error', 'auth_unconfigured');
      return NextResponse.redirect(url);
    }
    return supabaseResponse;
  }

  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
      {
        cookies: {
          get(name: string) {
            return request.cookies.get(name)?.value
          },
          set(name: string, value: string, options: CookieOptions) {
            request.cookies.set({
              name,
              value,
              ...options,
            })
            supabaseResponse = NextResponse.next({
              request: {
                headers: request.headers,
              },
            })
            supabaseResponse.cookies.set({
              name,
              value,
              ...options,
            })
          },
          remove(name: string, options: CookieOptions) {
            request.cookies.set({
              name,
              value: '',
              ...options,
            })
            supabaseResponse = NextResponse.next({
              request: {
                headers: request.headers,
              },
            })
            supabaseResponse.cookies.set({
              name,
              value: '',
              ...options,
            })
          },
        },
      }
    )

    const authHeaderUser = request.headers.get('authorization');
    const bearerTokenUser = authHeaderUser?.startsWith('Bearer ') ? authHeaderUser.substring(7).trim() : undefined;

    const {
      data: { user },
    } = await supabase.auth.getUser(bearerTokenUser)

    if (!user) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json({ error: 'Unauthorized: Authentication required' }, { status: 401 });
      }
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('next', pathname);
      return NextResponse.redirect(url);
    }

    // Master Admin route guard — strictly rely on server-managed role in app_metadata or validated user ID.
    // Client-writable user_metadata or unverified email fallbacks are forbidden.
    const isMasterAdmin =
      user.app_metadata?.role === 'master_admin' ||
      (Boolean(process.env.MASTER_ADMIN_USER_ID) && user.id === process.env.MASTER_ADMIN_USER_ID) ||
      (Boolean(process.env.MASTER_ADMIN_EMAIL) && (user.email || '').toLowerCase() === (process.env.MASTER_ADMIN_EMAIL || '').toLowerCase());

    if (pathname.startsWith('/console/system-admin')) {
      if (!isMasterAdmin) {
        const url = request.nextUrl.clone();
        url.pathname = '/console';
        return NextResponse.redirect(url);
      }
    }

    // Enterprise Admin route guard — server-validated plan in app_metadata or master admin
    if (pathname.startsWith('/console/admin')) {
      const isEnterprise =
        user.app_metadata?.plan === 'enterprise' ||
        user.app_metadata?.role === 'enterprise_admin' ||
        isMasterAdmin;
      if (!isEnterprise) {
        const url = request.nextUrl.clone();
        url.pathname = '/console';
        return NextResponse.redirect(url);
      }
    }
  } catch (err) {
    // P0.1: Authentication infrastructure failure must fail-closed (503 / 401) in production
    const isProd = process.env.NODE_ENV === 'production';
    const allowDevBypass = process.env.ALLOW_DEV_AUTH_BYPASS === 'true';

    if (isProd || !allowDevBypass) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json(
          { error: 'Service Unavailable: Authentication service failure' },
          { status: 503 }
        );
      }
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('error', 'auth_service_failure');
      return NextResponse.redirect(url);
    }
    return supabaseResponse;
  }

  return supabaseResponse
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
