#!/usr/bin/env python3
"""Full production scan — 1 hour, all queries, no limits."""
import sys, time, asyncio
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

def log_func(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERROR] "}.get(level, "")
    t = time.strftime("%H:%M:%S")
    print(f"[{t}] {prefix}{msg}")

# Load all queries
queries = list(BUILTIN_QUERIES)
print(f"Starting 1-hour scan with {len(queries)} queries")
print(f"Mode: max throughput, no limits")

engine = ScannerEngine(
    concurrency=25,       # Higher concurrency for more verification throughput
    timeout=15,
    search_delay=3.0,     # Slightly more conservative to avoid rate limits
    scan_pages=3,          # 3 pages = 300 results/query, sustainable for 1hr
    max_duration=3600,     # 1 hour
    max_valid_keys=0,      # NO limit — keep going
    output_dir="./results",
    log_callback=log_func,
)

t0 = time.time()
results = engine.run(queries)
elapsed = time.time() - t0

# Summary
valid = [r for r in results if r.get("valid")]
positive = [r for r in valid if r.get("balance_usd", 0) > 0]
zero = [r for r in valid if r.get("balance_usd", 0) == 0]
neg = [r for r in valid if r.get("balance_usd", 0) < 0]

print(f"\n{'='*60}")
print(f"1-HOUR SCAN COMPLETE")
print(f"{'='*60}")
print(f"Duration: {elapsed:.0f}s ({elapsed/60:.1f} min)")
print(f"Total keys found: {len(results)}")
print(f"  Valid: {len(valid)}")
print(f"  Positive balance: {len(positive)}")
print(f"  Zero balance: {len(zero)}")
print(f"  Negative balance: {len(neg)}")

if positive:
    total_usd = sum(r["balance_usd"] for r in positive)
    total_cny = sum(r["balance_cny"] for r in positive)
    print(f"\nTotal positive value: ${total_usd:.2f} / ¥{total_cny:.2f}")
    print(f"\nTop 30 positive keys:")
    for i, r in enumerate(sorted(positive, key=lambda x: x["balance_usd"], reverse=True)[:30]):
        cur = r.get("primary_currency", "USD")
        src = r["repos"][0].get("repo", "N/A") if r.get("repos") else "N/A"
        print(f"  {i+1:2d}. {r['key_preview']} | {cur} {r['balance']:.4f} | ${r['balance_usd']:.2f} | {src}")

print(f"\nResults saved to: ./results/deepseek_keys_result.json")
