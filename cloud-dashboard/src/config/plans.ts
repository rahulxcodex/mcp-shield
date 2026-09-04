export interface PlanTier {
  id: string;
  name: string;
  tagline: string;
  monthlyPriceUsd: number;
  annualPriceUsd: number;
  monthlyPriceInr: number;
  annualPriceInr: number;
  maxActiveKeys: number;
  singleUseEnforced: boolean;
  referralBenefitMonths: number;
  features: string[];
}

export const PLANS: Record<string, PlanTier> = {
  starter: {
    id: 'starter',
    name: 'Starter Plan',
    tagline: 'Full-featured AST security & DLP for individual developers and production MCP agents',
    monthlyPriceUsd: 1,      // 1 USD per month
    annualPriceUsd: 10,     // 10 USD per year (save ~17%)
    monthlyPriceInr: 85,    // 85 INR / mo equivalent
    annualPriceInr: 850,    // 850 INR / yr equivalent
    maxActiveKeys: 1,       // Strictly 1 active key with access per account
    singleUseEnforced: true, // Key once used/revoked cannot be reused
    referralBenefitMonths: 1, // 1 month free for referred users
    features: [
      '1 Dedicated Active Key with Access',
      'Full Tree-sitter AST Firewall (<0.18ms latency)',
      'Bijective DLP & Format-Preserving Encryption',
      'Zero-Trust Socket & TOCTOU Defense',
      'Single-Use Key Enforced (Prevents credential leakage)',
      '1 Month Free Referral Link for Colleagues',
      'SOC2 & HIPAA Compliance Export'
    ]
  },
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise Fleet',
    tagline: 'Multi-seat single key fleet deployment for organizations',
    monthlyPriceUsd: 499,
    annualPriceUsd: 4990,
    monthlyPriceInr: 39900,
    annualPriceInr: 399000,
    maxActiveKeys: 1,       // Single key fleet deployment (all seats share 1 cryptographically bounded key)
    singleUseEnforced: true,
    referralBenefitMonths: 1,
    features: [
      'Single Key Fleet Deployment (25-1,000 Seats)',
      'Private Enterprise Threat Corpus Access',
      'Custom AST Rules & Kill-Chain Detonation Defense',
      'Dedicated Customer Success & SLA'
    ]
  }
};

/**
 * Global Feature Flag:
 * App is currently deployed in introductory FREE ACCESS mode for a limited period.
 * Payment gateway UI is kept hidden until adoption milestones are reached.
 * All payment processing endpoints and business logic remain fully functional in code.
 */
export const FEATURE_FLAGS = {
  FREE_ACCESS_LIMITED_PERIOD: true,
  SHOW_PAYMENT_GATEWAYS: false, // Keep checkout UI hidden for introductory rollout
  ENFORCE_SINGLE_KEY_LIMIT: true,
  ENFORCE_KEY_NON_REUSABILITY: true,
  REFERRAL_SYSTEM_ENABLED: true
};
