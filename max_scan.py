#!/usr/bin/env python3
"""MAX throughput scan — 10 pages/query, 25 concurrency, full coverage."""
import sys, time, os, json
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

def log(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERR] "}.get(level, "")
    t = time.strftime("%m-%d %H:%M:%S")
    print(f"[{t}] {prefix}{msg}", flush=True)

# Load existing accumulated results
EXISTING = {}
existing_file = "results/deepseek_keys_final_backup.json"
if os.path.exists(existing_file):
    existing_data = json.load(open(existing_file, "r", encoding="utf-8"))
    for r in existing_data:
        EXISTING[r["key"]] = r
    log(f"Loaded {len(EXISTING)} existing keys from backup")

# All 69 queries, each query scans 10 pages = 1000 results max
queries = list(BUILTIN_QUERIES)
log(f"MAX SCAN: {len(queries)} queries x 5 pages x 100/query = 500 results max/query")
log(f"Settings: scan_pages=5, concurrency=25, page_delay=4s, search_delay=4s")
log(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")

engine = ScannerEngine(
    concurrency=25,
    timeout=15,
    search_delay=4.0,        # 4s between queries
    scan_pages=5,            # 5 pages = 500 results max per query
    max_duration=7200,        # 2 hours
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

t0 = time.time()
results = engine.run(queries)
elapsed = time.time() - t0

# Merge with existing
for r in results:
    if r["key"] not in EXISTING:
        EXISTING[r["key"]] = r
    else:
        # Update if balance changed
        old = EXISTING[r["key"]]
        if r.get("balance_usd", 0) != old.get("balance_usd", 0):
            EXISTING[r["key"]] = r
        else:
            # Keep old but add new repo info
            old_repos = {x["repo"] for x in old.get("repos", [])}
            for repo in r.get("repos", []):
                if repo["repo"] not in old_repos:
                    old.setdefault("repos", []).append(repo)

merged = sorted(EXISTING.values(), key=lambda x: x.get("balance_usd", 0), reverse=True)

# Save merged results
with open("results/deepseek_keys_result.json", "w", encoding="utf-8") as f:
    json.dump(merged, f, ensure_ascii=False, indent=2)

valid = [r for r in merged if r.get("valid")]
pos = [r for r in valid if r.get("balance_usd", 0) > 0]
zero = [r for r in valid if r.get("balance_usd", 0) == 0]
total_v = sum(r["balance_usd"] for r in pos)

log(f"\n{'='*60}")
log(f"MAX SCAN COMPLETE: {elapsed:.0f}s ({elapsed/60:.1f}min)")
log(f"New keys from this scan: {len(results)}")
log(f"Total accumulated: {len(merged)} keys")
log(f"  Positive: {len(pos)} | Zero: {len(zero)}")
log(f"TOTAL VALUE: ${total_v:.2f}")
if pos:
    log(f"\nTop 15:")
    for i, r in enumerate(pos[:15]):
        src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
        cur = r.get("primary_currency", "USD")
        log(f"  {i+1:2d}. {r['key_preview']} | {cur} {r['balance']:.4f} | ${r['balance_usd']:.2f} | {src[:50]}")
