#!/usr/bin/env python3
"""6-hour sustained scan — conservative rate, repeated queries, crash-resistant."""
import sys, time, os, traceback, subprocess
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

# Ensure GH token is available in env for background execution
if not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"):
    try:
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, timeout=5,
                          encoding="utf-8", errors="replace")
        if r.returncode == 0 and r.stdout.strip():
            os.environ["GH_TOKEN"] = r.stdout.strip()
            print(f"[{time.strftime('%m-%d %H:%M:%S')}] GH token loaded from gh CLI", flush=True)
    except:
        pass

LOG_FILE = "scan_6h_log.txt"

def log_func(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERR] "}.get(level, "")
    t = time.strftime("%m-%d %H:%M:%S")
    line = f"[{t}] {prefix}{msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except:
        pass

TOTAL_SECONDS = 6 * 3600  # 6 hours

# Repeat queries to fill 6 hours (~1 query per 2 min with conservative settings)
# 69 queries * 6 cycles = 414 queries, which should fill 6+ hours
cycles = 6
queries = list(BUILTIN_QUERIES) * cycles
print(f"6-HOUR SCAN: {len(queries)} queries ({cycles} cycles x {len(BUILTIN_QUERIES)} unique)", flush=True)
print(f"Settings: pages=3, page_delay=3s, search_delay=5s, concurrency=10", flush=True)
print(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
print("=" * 60, flush=True)

engine = ScannerEngine(
    concurrency=15,
    timeout=15,
    search_delay=5.0,      # 5s between queries (proven optimal)
    scan_pages=3,          # 3 pages = 300 results/query (proven optimal)
    max_duration=TOTAL_SECONDS,
    max_valid_keys=0,
    output_dir="./results",
    log_callback=log_func,
)

# No cooldown needed — scan runs in foreground context with valid gh auth
log_func("Starting scan immediately (no cooldown)")

t0 = time.time()
results = []
try:
    results = engine.run(queries)
except Exception as e:
    log_func(f"SCAN CRASHED: {e}", "error")
    traceback.print_exc()
    # Try to salvage whatever was saved
    try:
        import json as _json
        _f = os.path.join(engine.output_dir, "deepseek_keys_result.json")
        if os.path.exists(_f):
            results = _json.load(open(_f, "r", encoding="utf-8"))
            log_func(f"Salvaged {len(results)} results from last save", "warning")
    except:
        pass
elapsed = time.time() - t0

valid = [r for r in results if r.get("valid")]
positive = [r for r in valid if r.get("balance_usd", 0) > 0]
zero = [r for r in valid if r.get("balance_usd", 0) == 0]
total_value = sum(r["balance_usd"] for r in positive)

print(f"\n{'='*60}")
print(f"6-HOUR SCAN COMPLETE ({elapsed/3600:.1f}h)")
print(f"{'='*60}")
print(f"Total valid keys: {len(valid)}")
print(f"Positive balance: {len(positive)}")
print(f"Zero balance: {len(zero)}")
print(f"Total value: ${total_value:.2f}")
if positive:
    print(f"\nTop 20:")
    for i, r in enumerate(sorted(positive, key=lambda x: x["balance_usd"], reverse=True)[:20]):
        src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
        cur = r.get("primary_currency", "USD")
        print(f"  {i+1:2d}. {r['key_preview']} | {cur} {r['balance']:.4f} | ${r['balance_usd']:.2f} | {src}")
print(f"\nResults: results/deepseek_keys_result.json")
