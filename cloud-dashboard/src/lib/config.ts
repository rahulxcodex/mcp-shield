// Configuration & Environment Validation for Cloud Dashboard & Control Plane
export interface AppConfig {
  supabaseUrl: string;
  supabaseServiceKey: string;
  supabaseAnonKey: string;
  stripeSecretKey?: string;
  stripeWebhookSecret?: string;
  licensePrivateKey?: string;
  environment: 'development' | 'test' | 'production';
}

function validateConfiguration(): AppConfig {
  const env = (process.env.NODE_ENV || 'development') as AppConfig['environment'];
  const isProd = env === 'production';

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
  const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
  const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const licensePrivateKey = process.env.LICENSE_PRIVATE_KEY;

  const isBuildPhase = process.env.NEXT_PHASE === 'phase-production-build' || process.env.CI === 'true';

  if (isProd && !isBuildPhase) {
    const missing: string[] = [];
    if (!supabaseUrl || supabaseUrl.includes('placeholder') || supabaseUrl.includes('dummy')) {
      missing.push('NEXT_PUBLIC_SUPABASE_URL (must be a valid production URL)');
    }
    if (!supabaseServiceKey || supabaseServiceKey.includes('dummy') || supabaseServiceKey.includes('placeholder')) {
      missing.push('SUPABASE_SERVICE_ROLE_KEY (must be a valid high-entropy secret)');
    }
    if (!supabaseAnonKey || supabaseAnonKey.includes('dummy') || supabaseAnonKey.includes('placeholder')) {
      missing.push('NEXT_PUBLIC_SUPABASE_ANON_KEY');
    }
    if (missing.length > 0) {
      console.warn(`[MCP-SHIELD-DASHBOARD] Warning: Missing production variables: ${missing.join(', ')}`);
    }
  }

  return {
    supabaseUrl: supabaseUrl || 'https://magfptvxgxscmlzphhlq.supabase.co',
    supabaseServiceKey: supabaseServiceKey || 'test-service-key-for-local-mock-only',
    supabaseAnonKey: supabaseAnonKey || 'test-anon-key-for-local-mock-only',
    stripeSecretKey,
    stripeWebhookSecret,
    licensePrivateKey,
    environment: env,
  };
}

export const appConfig = validateConfiguration();
