#!/usr/bin/env bash
set -e

echo "⚡ Running MCP-Shield Reproducible Benchmarks..."

if command -v hyperfine &> /dev/null; then
    echo -e "\n[1/3] Executing Hyperfine Proxy Hot-Path Timing..."
    hyperfine --warmup 3 --runs 20 "node -e 'require(\"./dist/index.js\")'"
else
    echo -e "\n[1/3] Hyperfine not found on PATH. Using native high-precision performance.now() harness..."
fi

echo -e "\n[2/3] Executing Proxy Latency & AST Parsing Benchmarks..."
npx ts-node benchmarks/proxy-latency.bench.ts

echo -e "\n[3/3] Executing Labeled Secret Detection Precision & Recall Suite..."
npx ts-node benchmarks/secret-detection.bench.ts

echo -e "\n✅ Benchmarking completed. Generated BENCHMARKS.md."
