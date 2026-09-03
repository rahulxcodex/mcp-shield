'use client';

import { useState } from 'react';
import { CreditCard, Check, Zap } from 'lucide-react';

export default function BillingPage() {
  const [isUpgrading, setIsUpgrading] = useState(false);

  const [isRazorpayLoading, setIsRazorpayLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleRazorpayUpgrade = async () => {
    setIsRazorpayLoading(true);
    setSuccessMessage(null);
    try {
      const res = await fetch('/api/v1/billing/razorpay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'create-order', plan: 'pro' })
      });
      const data = await res.json();

      if (data?.simulation) {
        setSuccessMessage('Pro plan activated successfully (Test Simulation Mode).');
        return;
      }

      if (data?.orderId && data?.keyId) {
        // Load Razorpay checkout script if needed
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
          name: 'MCP Shield Pro',
          description: 'Monthly Pro Subscription',
          order_id: data.orderId,
          handler: async function (response: any) {
            const verifyRes = await fetch('/api/v1/billing/razorpay', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                action: 'verify-payment',
                plan: 'pro',
                razorpay_payment_id: response.razorpay_payment_id,
                razorpay_order_id: response.razorpay_order_id,
                razorpay_signature: response.razorpay_signature
              })
            });
            if (verifyRes.ok) {
              setSuccessMessage('Payment successful! Your account has been upgraded to Pro.');
            }
          },
          theme: {
            color: '#2563eb'
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

  const handleUpgrade = async () => {
    setIsUpgrading(true);
    try {
      const res = await fetch('/api/v1/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priceId: 'price_mcp_pro_monthly' })
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.url) {
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
    <div className="max-w-4xl">
      <h1 className="text-3xl font-bold mb-2 text-white">Billing & Plans</h1>
      <p className="text-slate-400 mb-8">Manage your subscription and billing details.</p>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Current Plan */}
        <div className="border border-slate-800 bg-slate-900 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-slate-800 rounded-md">
              <Zap className="h-6 w-6 text-slate-300" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">Free Plan</h3>
              <p className="text-sm text-slate-400">Your current plan</p>
            </div>
          </div>
          <p className="text-slate-300 mb-6">
            Basic features for personal use and small projects.
          </p>
          <ul className="space-y-3 mb-6">
            <li className="flex items-center gap-2 text-sm text-slate-300">
              <Check className="h-4 w-4 text-green-500" /> Up to 3 projects
            </li>
            <li className="flex items-center gap-2 text-sm text-slate-300">
              <Check className="h-4 w-4 text-green-500" /> Community support
            </li>
          </ul>
          <div className="inline-block px-4 py-2 border border-slate-700 text-slate-400 rounded-md bg-slate-800">
            Current Plan
          </div>
        </div>

        {/* Upgrade Plan */}
        <div className="border border-blue-500/50 bg-slate-900 rounded-lg p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 bg-blue-500 text-white text-xs font-bold px-3 py-1 rounded-bl-lg">
            RECOMMENDED
          </div>
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-blue-500/20 rounded-md">
              <CreditCard className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">Pro Plan</h3>
              <p className="text-sm text-blue-400">$29 / month</p>
            </div>
          </div>
          <p className="text-slate-300 mb-6">
            Advanced features for professionals and growing teams.
          </p>
          <ul className="space-y-3 mb-6">
            <li className="flex items-center gap-2 text-sm text-slate-300">
              <Check className="h-4 w-4 text-green-500" /> Unlimited projects
            </li>
            <li className="flex items-center gap-2 text-sm text-slate-300">
              <Check className="h-4 w-4 text-green-500" /> Priority support
            </li>
            <li className="flex items-center gap-2 text-sm text-slate-300">
              <Check className="h-4 w-4 text-green-500" /> Advanced analytics
            </li>
          </ul>
          
          {successMessage && (
            <div className="mb-4 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-md text-emerald-400 text-sm">
              {successMessage}
            </div>
          )}

          <div className="space-y-3">
            <button
              onClick={handleRazorpayUpgrade}
              disabled={isRazorpayLoading || isUpgrading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 px-4 rounded-md transition-colors disabled:opacity-50 flex justify-center items-center gap-2 text-sm shadow-sm"
            >
              {isRazorpayLoading ? 'Initializing...' : 'Pay with Razorpay (Cards, UPI, NetBanking)'}
            </button>
            <button
              onClick={handleUpgrade}
              disabled={isUpgrading || isRazorpayLoading}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium py-2 px-4 rounded-md transition-colors disabled:opacity-50 flex justify-center items-center gap-2 text-xs border border-slate-700"
            >
              {isUpgrading ? 'Loading...' : 'Pay with Stripe (International)'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
