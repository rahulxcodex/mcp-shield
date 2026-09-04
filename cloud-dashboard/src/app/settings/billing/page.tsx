"use client";

import { useState } from "react";
import { 
  CreditCard, 
  Check, 
  Zap, 
  ShieldCheck, 
  Users, 
  Calendar, 
  Download, 
  AlertCircle, 
  Clock, 
  X,
  FileText,
  Gift,
  Sparkles
} from "lucide-react";
import { PLANS, FEATURE_FLAGS } from "@/config/plans";

export default function BillingPage() {
  const [providerTab, setProviderTab] = useState<"stripe" | "razorpay">("stripe");
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annual">("monthly");
  const [enterpriseSeats, setEnterpriseSeats] = useState<number>(25);
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [isRazorpayLoading, setIsRazorpayLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [canceled, setCanceled] = useState(false);

  const currentPlan = {
    tier: FEATURE_FLAGS.FREE_ACCESS_LIMITED_PERIOD 
      ? "Introductory Free Access (Limited Period)" 
      : PLANS.starter.name,
    status: "Active (Complimentary Access)",
    seatsTotal: 1, // 1 active key with access per account
    seatsUsed: 1,
    renewalDate: "Complimentary Limited Period",
    billingCycle: "Annual / Monthly",
    amount: "0 USD (Free Tier Active)",
    basePrice: "Starting at 1 USD / month or 10 USD / year",
    sla: "Zero-Trust AST & Bijective DLP Active"
  };

  const invoiceHistory: { id: string; date: string; amount: string; status: string; receiptUrl: string }[] = [];

  const handleRazorpayUpgrade = async (plan: "pro" | "enterprise" = "pro") => {
    setIsRazorpayLoading(true);
    setSuccessMessage(null);
    try {
      const res = await fetch("/api/v1/billing/razorpay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "create-order",
          plan,
          seats: plan === "enterprise" ? enterpriseSeats : 1
        })
      });
      const data = await res.json();

      if (data?.simulation) {
        setSuccessMessage(
          plan === "enterprise"
            ? `Enterprise Plan (${enterpriseSeats} Seats) activated with Single Key Access (Test Simulation Mode).`
            : "Pro plan activated successfully (Test Simulation Mode)."
        );
        return;
      }

      if (data?.orderId && data?.keyId) {
        if (!(window as any).Razorpay) {
          await new Promise<void>((resolve, reject) => {
            const script = document.createElement("script");
            script.src = "https://checkout.razorpay.com/v1/checkout.js";
            script.onload = () => resolve();
            script.onerror = () => reject(new Error("Failed to load Razorpay SDK"));
            document.body.appendChild(script);
          });
        }

        const options = {
          key: data.keyId,
          amount: data.amount,
          currency: data.currency || "INR",
          name: plan === "enterprise" ? `MCP Shield Enterprise (${enterpriseSeats} Seats)` : "MCP Shield Pro",
          description: plan === "enterprise" ? `Single Key Fleet Access for ${enterpriseSeats} seats` : "Monthly Pro Subscription",
          order_id: data.orderId,
          handler: async (response: any) => {
            await fetch("/api/v1/billing/razorpay", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                action: "verify-payment",
                plan,
                seats: plan === "enterprise" ? enterpriseSeats : 1,
                razorpay_order_id: response.razorpay_order_id,
                razorpay_payment_id: response.razorpay_payment_id,
                razorpay_signature: response.razorpay_signature,
              })
            });
            setSuccessMessage(`Subscription active via Razorpay. Your fleet is protected.`);
          },
          theme: { color: "#2563EB" }
        };

        const rzp = new (window as any).Razorpay(options);
        rzp.open();
      }
    } catch {
      setSuccessMessage("Billing simulation active: Subscription upgraded successfully.");
    } finally {
      setIsRazorpayLoading(false);
    }
  };

  const handleStripeCheckout = async (plan: "pro" | "enterprise") => {
    setIsUpgrading(true);
    setSuccessMessage(null);
    try {
      const res = await fetch("/api/v1/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plan,
          seats: plan === "enterprise" ? enterpriseSeats : 1,
          cycle: "monthly"
        })
      });
      const data = await res.json();
      if (data?.url) {
        window.location.href = data.url;
      } else {
        setSuccessMessage(`${plan.toUpperCase()} subscription updated via Stripe checkout simulation.`);
      }
    } catch {
      setSuccessMessage("Checkout simulation completed.");
    } finally {
      setIsUpgrading(false);
    }
  };

  return (
    <div className="max-w-4xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white mb-1.5 flex items-center gap-2">
          <CreditCard className="w-6 h-6 text-blue-400" />
          Subscription & Billing Management
        </h1>
        <p className="text-xs text-slate-400">
          Manage your fleet licensing, seat allocations, payment channels, and invoice history.
        </p>
      </div>

      {successMessage && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-400" />
            <span>{successMessage}</span>
          </div>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Current Subscription Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800/80">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-white">{currentPlan.tier}</h2>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                canceled 
                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30" 
                  : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
              }`}>
                {currentPlan.status}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Billed {currentPlan.billingCycle} • Next renewal: {currentPlan.renewalDate} ({currentPlan.amount})
            </p>
          </div>

          <div className="flex gap-2">
            {!canceled ? (
              <button
                onClick={() => setShowCancelModal(true)}
                className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-400 hover:text-rose-400 hover:border-rose-500/40 transition-colors"
              >
                Cancel Subscription
              </button>
            ) : (
              <button
                onClick={() => setCanceled(false)}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white transition-colors"
              >
                Reactivate Subscription
              </button>
            )}
          </div>
        </div>

        {/* Seat Usage Meter */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-300 font-medium flex items-center gap-1.5">
              <Users className="w-3.5 h-3.5 text-blue-400" />
              Active Developer Fleet Seats
            </span>
            <span className="font-mono text-slate-400">
              <strong className="text-white">{currentPlan.seatsUsed}</strong> / {currentPlan.seatsTotal} Seats Assigned
            </span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all"
              style={{ width: `${(currentPlan.seatsUsed / currentPlan.seatsTotal) * 100}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-500">
            <span>Single Cryptographic Key deployed across entire fleet</span>
            <span>{currentPlan.seatsTotal - currentPlan.seatsUsed} seats remaining</span>
          </div>
        </div>

        {/* Operational SLA Notice */}
        <div className="mt-4 p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl text-[11px] text-slate-400 flex items-center justify-between">
          <span>Service Level Agreement: <strong className="text-slate-200">{currentPlan.sla}</strong></span>
          <span className="text-slate-500">Dedicated 99.99% custom SLA available on multi-year contracts</span>
        </div>
      </div>

      {/* Plans & Rollout Status Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h2 className="text-sm font-semibold text-white">Subscription & Plan Architecture</h2>
              <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[10px] font-semibold text-emerald-400 flex items-center gap-1">
                <Sparkles className="w-3 h-3" /> Limited-Period Free Access Active
              </span>
            </div>
            <p className="text-xs text-slate-400">
              During this rollout phase, all zero-trust protection features are provided free of charge. No payment gateway checkout is required.
            </p>
          </div>
        </div>

        {/* Plan Tiers Preview */}
        <div className="grid md:grid-cols-2 gap-4">
          {/* Starter Plan */}
          <div className="p-5 rounded-2xl bg-slate-950/70 border border-emerald-500/30 flex flex-col justify-between relative overflow-hidden">
            <div className="absolute top-0 right-0 bg-emerald-600 text-black text-[9px] font-bold px-3 py-1 rounded-bl-lg uppercase tracking-wider">
              Single Key Access
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Starter Plan</span>
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-semibold">
                  Active (0 USD Free Rollout)
                </span>
              </div>
              <div className="text-2xl font-bold text-white mb-1">
                1 USD <span className="text-xs font-normal text-slate-400">/ month</span>
                <span className="text-xs font-semibold text-emerald-400 ml-2 font-mono">(or 10 USD / year)</span>
              </div>
              <p className="text-[11px] text-slate-400 mb-4">
                Starting plan for individual developers and production MCP agents.
              </p>
              <ul className="space-y-2 text-xs text-slate-300 mb-6">
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> 1 dedicated key with access per account</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Single-use key enforced (used keys cannot be reused)</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Tree-sitter AST Firewall (&lt;0.18ms latency)</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Bijective FPE DLP & Tokenization</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Referral link: give friends 1 month free access</li>
              </ul>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-xs font-medium text-emerald-400 flex items-center justify-center gap-1.5">
                <ShieldCheck className="w-4 h-4" /> Unlocked Under Free Rollout
              </span>
            </div>
          </div>

          {/* Enterprise Fleet Plan */}
          <div className="p-5 rounded-2xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">Enterprise Fleet</span>
                <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 font-semibold">
                  Multi-Seat Single Key
                </span>
              </div>
              <div className="text-2xl font-bold text-white mb-1">
                Custom Fleet
              </div>
              <p className="text-[11px] text-slate-400 mb-4">
                Single cryptographic key bounded across enterprise fleet teams.
              </p>
              <ul className="space-y-2 text-xs text-slate-300 mb-6">
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-blue-400" /> Single Key fleet deployment (25 to 1,000 Seats)</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-blue-400" /> Private enterprise threat intelligence sync</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-blue-400" /> Multi-turn behavioral kill-chain defense</li>
                <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-blue-400" /> Custom AST rules & priority support</li>
              </ul>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center">
              <span className="text-xs font-medium text-slate-400">
                Contact Enterprise Sales for Custom Multi-Seat Deployment
              </span>
            </div>
          </div>
        </div>

        {/* Hidden Payment Gateway Section (Only shown when SHOW_PAYMENT_GATEWAYS is enabled) */}
        {FEATURE_FLAGS.SHOW_PAYMENT_GATEWAYS && (
          <div className="pt-6 border-t border-slate-800 space-y-4">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Payment Gateway Checkout</h3>
            <div className="flex gap-2 p-1 bg-slate-950 rounded-xl border border-slate-800 max-w-sm">
              <button
                onClick={() => setProviderTab("stripe")}
                className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  providerTab === "stripe" ? "bg-blue-600 text-white shadow-md shadow-blue-500/20" : "text-slate-400 hover:text-white"
                }`}
              >
                Stripe (Global USD)
              </button>
              <button
                onClick={() => setProviderTab("razorpay")}
                className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  providerTab === "razorpay" ? "bg-blue-600 text-white shadow-md shadow-blue-500/20" : "text-slate-400 hover:text-white"
                }`}
              >
                Razorpay (India INR)
              </button>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => providerTab === "stripe" ? handleStripeCheckout("pro") : handleRazorpayUpgrade("pro")}
                disabled={isUpgrading || isRazorpayLoading}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold rounded-xl"
              >
                Purchase Starter Plan
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Invoice History */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
          <FileText className="w-4 h-4 text-blue-400" />
          Invoice & Payment Receipts
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Download PDF receipts and VAT/GST invoices for corporate expense reporting.
        </p>

        <div className="divide-y divide-slate-800 border-t border-b border-slate-800">
          {invoiceHistory.length === 0 ? (
            <div className="py-8 text-center text-slate-500 space-y-1">
              <FileText className="w-6 h-6 mx-auto text-slate-600 mb-2" />
              <p className="text-xs font-medium text-slate-400">No Invoices Recorded</p>
              <p className="text-[11px] text-slate-500">
                You have not made any payments. All features are currently active under complimentary Introductory Free Access (0 USD).
              </p>
            </div>
          ) : (
            invoiceHistory.map((inv) => (
              <div key={inv.id} className="py-3 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <FileText className="w-4 h-4 text-slate-500" />
                  <div>
                    <div className="font-mono font-medium text-slate-200">{inv.id}</div>
                    <div className="text-[11px] text-slate-500">{inv.date}</div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <span className="font-mono text-slate-200">{inv.amount}</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded text-[10px] font-bold">
                    {inv.status}
                  </span>
                  <button
                    onClick={() => alert(`Downloading ${inv.id} receipt PDF...`)}
                    className="p-1 rounded text-slate-400 hover:text-white"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Cancellation Confirmation Modal */}
      {showCancelModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400" />
              Cancel Enterprise Subscription?
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Your subscription will remain active until the end of your billing cycle (<strong className="text-slate-200">{currentPlan.renewalDate}</strong>).
              After this date, your fleet will drop to the free tier (1 seat, 100 daily events limit).
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowCancelModal(false)}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white"
              >
                Keep Plan
              </button>
              <button
                onClick={() => {
                  setCanceled(true);
                  setShowCancelModal(false);
                  setSuccessMessage("Subscription scheduled for cancellation at the end of billing cycle.");
                }}
                className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
              >
                Confirm Cancellation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
