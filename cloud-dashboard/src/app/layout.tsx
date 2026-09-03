import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import StructuredData from "@/components/StructuredData";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const viewport: Viewport = {
  themeColor: "#090a0f",
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || "https://mcpshield.dev"),
  title: {
    default: "MCP Shield — Zero-Trust Security Gateway & Firewall for Model Context Protocol",
    template: "%s | MCP Shield",
  },
  description:
    "Production-grade Zero-Trust reverse proxy and firewall for Model Context Protocol (MCP) and AI agents. Tree-sitter AST command injection defense, bijective FPE DLP secret tokenization, and SSRF cloud metadata protection in under 0.2ms.",
  keywords: [
    "mcp security",
    "mcp security software",
    "model context protocol security",
    "mcp firewall",
    "ai agent security",
    "claude desktop mcp proxy",
    "cursor mcp firewall",
    "ast command injection defense",
    "mcp dlp",
    "llm agent guardrails",
    "zero trust ai gateway",
    "antigravity mcp security",
    "prompt injection defense",
    "ebpf ai proxy",
  ],
  authors: [{ name: "MCP Shield Project", url: "https://github.com/rahulxcodex/mcp-shield" }],
  creator: "MCP Shield Project",
  publisher: "MCP Shield",
  alternates: {
    canonical: "/",
  },
  openGraph: {
    title: "MCP Shield — Zero-Trust Security Gateway & Firewall for Model Context Protocol",
    description:
      "Enterprise Zero-Trust firewall, AST-level command inspection, bijective DLP secret redaction, and SSRF prevention for Model Context Protocol (MCP) and AI agents.",
    url: "https://mcpshield.dev",
    siteName: "MCP Shield",
    locale: "en_US",
    type: "website",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "MCP Shield Zero-Trust Security Gateway for Model Context Protocol",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "MCP Shield — Zero-Trust Security Gateway for AI Agents",
    description:
      "Protect your AI agent workflows from prompt injection, AST command manipulation, and secret leakage in under 0.2ms latency.",
    images: ["/og-image.png"],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased scroll-smooth`}
    >
      <body className="min-h-full flex flex-col bg-[#090a0f] text-slate-100 selection:bg-emerald-500/30 selection:text-emerald-300">
        <StructuredData />
        {children}
      </body>
    </html>
  );
}
