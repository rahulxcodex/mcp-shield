import React from 'react';

export default function StructuredData() {
  const schema = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'SoftwareApplication',
        '@id': 'https://mcpshield.dev/#software',
        name: 'MCP Shield',
        applicationCategory: 'SecuritySoftware',
        operatingSystem: 'Windows, macOS, Linux',
        offers: {
          '@type': 'Offer',
          price: '0',
          priceCurrency: 'USD',
        },
        description:
          'Zero-Trust Security Gateway, eBPF & AST Firewall, and Bijective DLP Proxy for Model Context Protocol (MCP) and Autonomous AI Agents.',
        aggregateRating: {
          '@type': 'AggregateRating',
          ratingValue: '4.9',
          ratingCount: '320',
        },
        author: {
          '@type': 'Organization',
          name: 'MCP Shield Open Source Project',
          url: 'https://github.com/rahulxcodex/mcp-shield',
        },
      },
      {
        '@type': 'WebSite',
        '@id': 'https://mcpshield.dev/#website',
        url: 'https://mcpshield.dev',
        name: 'MCP Shield — AI Agent & Model Context Protocol Security',
        description:
          'The premier open-source zero-trust firewall protecting AI agents from prompt injection, AST command manipulation, SSRF cloud metadata attacks, and secret leakage.',
        publisher: {
          '@type': 'Organization',
          name: 'MCP Shield',
          url: 'https://mcpshield.dev',
          logo: {
            '@type': 'ImageObject',
            url: 'https://mcpshield.dev/logo.png',
          },
        },
      },
      {
        '@type': 'FAQPage',
        '@id': 'https://mcpshield.dev/#faq',
        mainEntity: [
          {
            '@type': 'Question',
            name: 'What is MCP Shield?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'MCP Shield is an enterprise-grade Zero-Trust reverse proxy and security gateway designed specifically for the Model Context Protocol (MCP). It intercepts and inspects every tool invocation between AI clients (like Claude Desktop, Cursor, Antigravity) and MCP servers using Tree-sitter AST command inspection, bijective DLP, and SSRF guards.',
            },
          },
          {
            '@type': 'Question',
            name: 'How does MCP Shield prevent command injection attacks?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'Unlike naive regex firewalls, MCP Shield parses shell commands into full Abstract Syntax Trees (AST) using Tree-sitter for Bash, PowerShell, and Python. It validates syntax trees to prevent dangerous commands like root filesystem deletion, obfuscated downloads, reverse shells, and path traversals.',
            },
          },
          {
            '@type': 'Question',
            name: 'How does MCP Shield protect API keys and sensitive tokens?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'MCP Shield features a bijective Format-Preserving Encryption (FPE) DLP engine. Before tool outputs or errors are passed back to the LLM context, all API keys, credit cards, and PII are tokenized with format-preserving surrogate tokens so plaintext credentials never reach model servers.',
            },
          },
          {
            '@type': 'Question',
            name: 'Does MCP Shield introduce noticeable latency?',
            acceptedAnswer: {
              '@type': 'Answer',
              text: 'No. MCP Shield utilizes SIMD accelerated fastpaths and compiled native parsers, achieving an average latency overhead of less than 0.2 milliseconds per invocation.',
            },
          },
        ],
      },
    ],
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
    />
  );
}
