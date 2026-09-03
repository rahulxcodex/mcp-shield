'use client';

import { useState } from 'react';
import { CreditCard, Check, Zap } from 'lucide-react';

export default function BillingPage() {
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [isRazorpayLoading, setIsRazorpayLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [enterpriseSeats, setEnterpriseSeats] = useState<number>(25);

  const enterpriseSeatPricing: Record<number, { usd: string; inr: string; label: string }> = {
    25: { usd: '$499', inr: '₹39,900', label: '25 Seats' },
    50: { usd: '$899', inr: '₹69,900', label: '50 Seats' },
    100: { usd: '$1,499', inr: '₹1,19,900', label: '100 Seats' },
    500: { usd: '$4,999', inr: '₹3,99,900', label: '500 Seats' },
    1000: { usd: '$8,999', inr: '₹6,99,900', label: '1,000 Seats' },
  };

  const handleRazorpayUpgrade = async (plan: 'pro' | 'enterprise' = 'pro') => {
    setIsRazorpayLoading(true);
    setSuccessMessage(null);
    try {
      const res = await fetch('/api/v1/billing/razorpay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'create-order',
          plan,
          seats: plan === 'enterprise' ? enterpriseSeats : 1
        })
      });
      const data = await res.json();

      if (data?.simulation) {
        setSuccessMessage(
          plan === 'enterprise'
            ? `Enterprise Plan (${enterpriseSeats} Seats) activated successfully with Single Key Access (Test Simulation Mode).`
            : 'Pro plan activated successfully (Test Simulation Mode).'
        );
        return;
      }

      if (data?.orderId && data?.keyId) {
        if (!(window as any).Razorpay) {
          await new Promise<void>((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://checkout.razorpay.com/v1/checkout.js';
            script.onload = () => resolve();
            script.onerror = () => reject(new Error('Failed to load Razorpay SDK'));
            document.body.appendChild(script);
          });
        }

        const options = {
          key: data.keyId,
          amount: data.amount,
          currency: data.currency || 'INR',
          name: plan === 'enterprise' ? `MCP Shield Enterprise (${enterpriseSeats} Seats)` : 'MCP Shield Pro',
          description: plan === 'enterprise' ? `Single Key Fleet Access for ${enterpriseSeats} seats` : 'Monthly Pro Subscription',
          order_id: data.orderId,
          handler: async function (response: any) {
            const verifyRes = await fetch('/api/v1/billing/razorpay', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                action: 'verify-payment',
                plan,
                seats: plan === 'enterprise' ? enterpriseSeats : 1,
                razorpay_payment_id: response.razorpay_payment_id,
                razorpay_order_id: response.razorpay_order_id,
                razorpay_signature: response.razorpay_signature
              })
            });
            if (verifyRes.ok) {
              setSuccessMessage(
                plan === 'enterprise'
                  ? `Payment successful! Enterprise Plan (${enterpriseSeats} Seats) activated with a single key.`
                  : 'Payment successful! Your account has been upgraded to Pro.'
              );
            }
          },
          theme: {
            color: plan === 'enterprise' ? '#10b981' : '#2563eb'
          }
        };

        const rzp = new (window as any).Razorpay(options);
        rzp.open();
      }
    } catch (error: any) {
      console.error('Razorpay checkout error:', error);
      alert(error.message || 'Failed to initialize Razorpay checkout');
    } finally {
      setIsRazorpayLoading(false);
    }
  };

  const handleUpgrade = async (plan: 'pro' | 'enterprise' = 'pro') => {
    setIsUpgrading(true);
    try {
      const res = await fetch('/api/v1/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          plan,
          seats: plan === 'enterprise' ? enterpriseSeats : 1,
          priceId: plan === 'enterprise' ? `price_mcp_enterprise_${enterpriseSeats}` : 'price_mcp_pro_monthly'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.simulation) {
          setSuccessMessage(
            plan === 'enterprise'
              ? `Enterprise Plan (${enterpriseSeats} Seats) activated with Single Key Access (Simulation Mode).`
              : 'Pro Plan activated successfully (Simulation Mode).'
          );
        } else if (data?.url) {
          window.location.href = data.url;
        }
      }
    } catch (error) {
      console.error('Failed to upgrade:', error);
    } finally {
      setIsUpgrading(false);
    }
  };

  return (
    <div className="max-w-6xl">
      <h1 className="text-3xl font-bold mb-2 text-white">Billing & Plans</h1>
      <p className="text-slate-400 mb-8">Manage subscriptions, team seats, and zero-trust single key deployments.</p>

      {successMessage && (
        <div className="mb-6 p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400 text-sm font-medium flex items-center gap-2">
          <Check className="w-5 h-5 text-emerald-400 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Free Plan */}
        <div className="border border-slate-800 bg-slate-900/90 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 bg-slate-800 rounded-xl">
                <Zap className="h-6 w-6 text-slate-300" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Free Plan</h3>
                <p className="text-sm text-slate-400">Personal Developer</p>
              </div>
            </div>
            <p className="text-slate-300 text-sm mb-6">
              Basic security gateway for personal testing and open source development.
            </p>
            <ul className="space-y-3 mb-6">
              <li className="flex items-center gap-2 text-sm text-slate-300">
                <Check className="h-4 w-4 text-emerald-500" /> 1 seat / single device
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-300">
                <Check className="h-4 w-4 text-emerald-500" /> Up to 3 projects
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-300">
                <Check className="h-4 w-4 text-emerald-500" /> Standard AST inspection
              </li>
            </ul>
          </div>
          <div className="w-full text-center py-2.5 border border-slate-700 text-slate-400 rounded-xl bg-slate-800 text-xs font-semibold">
            Current Plan
          </div>
        </div>

        {/* Pro Plan */}
        <div className="border border-blue-500/50 bg-slate-900/90 rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 bg-blue-500/20 rounded-xl">
                <CreditCard className="h-6 w-6 text-blue-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Pro Plan</h3>
                <p className="text-sm text-blue-400 font-semibold">$29 / month</p>
              </div>
            </div>
            <p className="text-slate-300 text-sm mb-6">
              Advanced security features for individual professionals and indie developers.
            </p>
            <ul className="space-y-3 mb-6">
              <li className="flex items-center gap-2 text-sm text-slate-300">
                <Check className="h-4 w-4 text-blue-400" /> Unlimited projects & servers
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-300">
                <Check className="h-4 w-4 text-blue-400" /> Bijective FPE DLP Sanitization
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-300">
                <Check className="h-4 w-4 text-blue-400" /> Live Threat Intercept Telemetry
              </li>
            </ul>
          </div>

          <div className="space-y-2.5 pt-4 border-t border-slate-800">
            <button
              onClick={() => handleRazorpayUpgrade('pro')}
              disabled={isRazorpayLoading || isUpgrading}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 px-4 rounded-xl transition disabled:opacity-50 text-xs shadow-md cursor-pointer"
            >
              {isRazorpayLoading ? 'Processing...' : 'Upgrade to Pro (Razorpay / UPI / Cards)'}
            </button>
            <button
              onClick={() => handleUpgrade('pro')}
              disabled={isUpgrading || isRazorpayLoading}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold py-2 px-4 rounded-xl transition disabled:opacity-50 text-xs border border-slate-700 cursor-pointer"
            >
              {isUpgrading ? 'Loading...' : 'Pay with Stripe'}
            </button>
          </div>
        </div>

        {/* Enterprise Plan (Single Key Multi-Seat Access) */}
        <div className="border-2 border-emerald-500/60 bg-gradient-to-b from-slate-900 to-[#0b1319] rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between shadow-xl shadow-emerald-500/10">
          <div className="absolute top-0 right-0 bg-gradient-to-l from-emerald-500 to-teal-500 text-black text-[10px] font-extrabold px-3 py-1 rounded-bl-xl tracking-wider">
            SINGLE KEY ACCESS
          </div>

          <div>
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2.5 bg-emerald-500/20 rounded-xl">
                <Zap className="h-6 w-6 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-extrabold text-white">Enterprise Plan</h3>
                <div className="flex items-baseline gap-2">
                  <span className="text-xl font-black text-emerald-400">
                    {enterpriseSeatPricing[enterpriseSeats]?.usd}
                  </span>
                  <span className="text-xs text-slate-400">
                    / mo ({enterpriseSeatPricing[enterpriseSeats]?.inr})
                  </span>
                </div>
              </div>
            </div>

            <p className="text-slate-300 text-xs mb-4">
              Deploy a <strong>single cryptographic key</strong> across your entire developer organization with corporate email validation.
            </p>

            {/* Seat Tier Selector: 25, 50, 100, 500, 1000 */}
            <div className="mb-4">
              <label className="block text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Select Team Access Capacity (Single Key)
              </label>
              <div className="grid grid-cols-5 gap-1.5 p-1 bg-slate-950/80 border border-slate-800 rounded-xl">
                {[25, 50, 100, 500, 1000].map((seats) => (
                  <button
                    key={seats}
                    type="button"
                    onClick={() => setEnterpriseSeats(seats)}
                    className={`py-1.5 px-1 rounded-lg text-xs font-bold transition cursor-pointer text-center ${
                      enterpriseSeats === seats
                        ? 'bg-emerald-500 text-black shadow-md shadow-emerald-500/30'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    {seats}
                  </button>
                ))}
              </div>
              <div className="text-[11px] text-emerald-400/90 font-medium mt-1.5 flex items-center gap-1">
                <Check className="w-3.5 h-3.5" />
                <span>Single master key unlocks access for up to <strong>{enterpriseSeats} seats</strong></span>
              </div>
            </div>

            <ul className="space-y-2.5 mb-6 text-xs text-slate-300">
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                <span><strong>Single Enterprise License Key</strong> for all {enterpriseSeats} engineers</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>Enterprise Domain Login (Restricted to <strong>@domain.com</strong>)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>Fleet-wide live telemetry, threat blocking, and audit exporter</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>Dedicated AST cluster & 99.99% enterprise uptime SLA</span>
              </li>
            </ul>
          </div>

          <div className="space-y-2.5 pt-4 border-t border-slate-800/80">
            <button
              onClick={() => handleRazorpayUpgrade('enterprise')}
              disabled={isRazorpayLoading || isUpgrading}
              className="w-full bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-black font-extrabold py-2.5 px-4 rounded-xl transition disabled:opacity-50 text-xs shadow-lg shadow-emerald-500/20 cursor-pointer"
            >
              {isRazorpayLoading ? 'Processing...' : `Deploy Single Key (${enterpriseSeats} Seats) - Razorpay`}
            </button>
            <button
              onClick={() => handleUpgrade('enterprise')}
              disabled={isUpgrading || isRazorpayLoading}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold py-2 px-4 rounded-xl transition disabled:opacity-50 text-xs border border-slate-700 cursor-pointer"
            >
              {isUpgrading ? 'Loading...' : `Deploy Single Key (${enterpriseSeats} Seats) - Stripe`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
