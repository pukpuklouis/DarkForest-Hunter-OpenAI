#!/usr/bin/env python3
"""Marathon scan: runs in 20-min batches, accumulates results, survives restarts.
Each batch scans all 69 queries once, saves, then restarts.
Total runtime: configurable (default 6 hours for 18 batches)."""
import sys, time, os, json
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

BATCH_MINUTES = 20
TOTAL_HOURS = 6
OUTPUT = "results/deepseek_keys_result.json"
PROGRESS_FILE = "results/.marathon_progress.json"

def log(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERR] "}.get(level, "")
    t = time.strftime("%m-%d %H:%M:%S")
    line = f"[{t}] {prefix}{msg}"
    print(line, flush=True)
    try:
        with open("marathon_log.txt", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except: pass

def load_accumulated():
    if os.path.exists(OUTPUT):
        try:
            return json.load(open(OUTPUT, "r", encoding="utf-8"))
        except: pass
    return []

def save_accumulated(results):
    os.makedirs("results", exist_ok=True)
    engine = ScannerEngine()  # just for sort
    sorted_r = engine.sort_results(results)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(sorted_r, f, ensure_ascii=False, indent=2)

def merge(existing, new_results):
    seen = {r["key"] for r in existing}
    for r in new_results:
        if r["key"] not in seen:
            existing.append(r)
            seen.add(r["key"])
    return existing

# Main
log(f"MARATHON SCAN: {TOTAL_HOURS}h target, {BATCH_MINUTES}min batches")
log(f"Accumulating to: {OUTPUT}")

accumulated = load_accumulated()
log(f"Loaded {len(accumulated)} existing results")

batch = 0
t0 = time.time()
deadline = t0 + TOTAL_HOURS * 3600

while time.time() < deadline:
    batch += 1
    remaining = deadline - time.time()
    batch_duration = min(BATCH_MINUTES * 60, remaining)
    if batch_duration < 60:
        break

    log(f"\n{'='*50}")
    log(f"BATCH {batch}: starting ({batch_duration/60:.0f}min, {remaining/3600:.1f}h remaining)")
    log(f"  Accumulated so far: {len(accumulated)} keys")

    engine = ScannerEngine(
        concurrency=15, timeout=15, search_delay=5.0,
        scan_pages=3, max_duration=batch_duration, max_valid_keys=0,
        output_dir="./results", log_callback=log,
    )

    batch_results = engine.run(BUILTIN_QUERIES)
    accumulated = merge(accumulated, batch_results)
    save_accumulated(accumulated)

    pos = [r for r in accumulated if r.get("valid") and r.get("balance_usd", 0) > 0]
    total = sum(r["balance_usd"] for r in pos)
    log(f"BATCH {batch} DONE: {len(batch_results)} new, {len(accumulated)} total, {len(pos)} positive, ${total:.2f}")

    if time.time() >= deadline:
        break
    # Brief pause between batches
    time.sleep(5)

elapsed = (time.time() - t0) / 3600
pos = [r for r in accumulated if r.get("valid") and r.get("balance_usd", 0) > 0]
total = sum(r["balance_usd"] for r in pos)
log(f"\n{'='*60}")
log(f"MARATHON COMPLETE: {elapsed:.1f}h, {batch} batches, {len(accumulated)} keys, {len(pos)} positive, ${total:.2f}")
