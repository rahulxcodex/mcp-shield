# MCP-Shield Hyperfine & Node Micro-Benchmark Reproducibility Script
Write-Host "⚡ Running MCP-Shield Reproducible Benchmarks..." -ForegroundColor Cyan

# 1. Check if hyperfine is installed
if (Get-Command hyperfine -ErrorAction SilentlyContinue) {
    Write-Host "`n[1/3] Executing Hyperfine Proxy Hot-Path CLI Timing..." -ForegroundColor Green
    hyperfine --warmup 3 --runs 20 "node -e 'require(\"./dist/index.js\")'"
} else {
    Write-Host "`n[1/3] Hyperfine not detected on PATH. Using native micro-benchmark harness..." -ForegroundColor Yellow
}

# 2. Run proxy latency and throughput benchmark
Write-Host "`n[2/3] Executing Proxy Latency & AST Parsing Benchmarks..." -ForegroundColor Green
npx ts-node benchmarks/proxy-latency.bench.ts

# 3. Run Labeled DLP Precision & Recall Benchmark
Write-Host "`n[3/3] Executing Labeled Secret Detection Precision & Recall Suite..." -ForegroundColor Green
npx ts-node benchmarks/secret-detection.bench.ts

Write-Host "`n✅ Benchmarking completed. Updated BENCHMARKS.md." -ForegroundColor Cyan
