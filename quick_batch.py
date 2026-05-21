#!/usr/bin/env python3
"""Quick batch scan: runs 4 min, accumulates, exits cleanly. Cron-friendly."""
import sys, time, os, json
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

OUTPUT = "results/deepseek_keys_result.json"
LOG = "results/batch_log.txt"
DURATION = 240  # 4 minutes

os.makedirs("results", exist_ok=True)

def log(msg):
    t = time.strftime("%m-%d %H:%M:%S")
    line = f"[{t}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except: pass

# Cross-platform file locking (Windows-compatible)
LOCK_FILE = OUTPUT + ".lock"

def acquire_lock():
    """Simple file-based lock. Returns lockfd or None."""
    for _ in range(30):
        try:
            lockfd = open(LOCK_FILE, "x")  # exclusive create — fails if exists
            lockfd.write(str(os.getpid()))
            lockfd.flush()
            return lockfd
        except FileExistsError:
            time.sleep(1)
    # Stale lock recovery: if lock older than 5 min, break it
    if os.path.exists(LOCK_FILE):
        if time.time() - os.path.getmtime(LOCK_FILE) > 300:
            os.remove(LOCK_FILE)
            try:
                lockfd = open(LOCK_FILE, "x")
                lockfd.write(str(os.getpid()))
                return lockfd
            except:
                pass
    log("WARNING: Could not acquire lock after 30s", "error")
    return None

def release_lock(lockfd):
    try:
        lockfd.close()
        os.remove(LOCK_FILE)
    except:
        pass

# Load existing (with auto-recovery from backup)
BACKUP = OUTPUT.replace(".json", ".backup.json")
existing = []
if os.path.exists(OUTPUT):
    try:
        existing = json.load(open(OUTPUT, "r", encoding="utf-8"))
    except:
        log(f"WARNING: corrupt file, restoring from backup", "error")
        existing = []
if os.path.exists(BACKUP):
    try:
        backup_data = json.load(open(BACKUP, "r", encoding="utf-8"))
        # Auto-recover if backup has significantly more keys
        if len(backup_data) > len(existing) * 1.2:
            log(f"Recovering from backup: {len(existing)} -> {len(backup_data)} keys")
            existing = backup_data
    except:
        pass

existing_keys = {r["key"] for r in existing}
n_before = len(existing)

log(f"BATCH SCAN: {len(existing)} existing keys, running {DURATION}s...")

engine = ScannerEngine(
    concurrency=15, timeout=15, search_delay=4.0,
    scan_pages=3, max_duration=DURATION, max_valid_keys=0,
    output_dir="./results/.tmp_batch",
)

new_results = engine.run(BUILTIN_QUERIES)

# Merge
added = 0
for r in new_results:
    if r["key"] not in existing_keys:
        existing.append(r)
        existing_keys.add(r["key"])
        added += 1

# Sort and save with file locking
existing.sort(key=lambda x: x.get("balance_usd", 0), reverse=True)

lockfd = acquire_lock()
if lockfd:
    import tempfile, shutil
    tmpfd, tmppath = tempfile.mkstemp(dir="results", suffix=".json")
    try:
        with os.fdopen(tmpfd, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
        shutil.move(tmppath, OUTPUT)
        shutil.copy2(OUTPUT, BACKUP)
    except:
        os.unlink(tmppath)
        raise
    finally:
        release_lock(lockfd)
else:
    log("WARNING: Could not acquire lock, saving without lock", "error")
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

pos = [r for r in existing if r.get("valid") and r.get("balance_usd", 0) > 0]
total = sum(r["balance_usd"] for r in pos)
elapsed = time.time() - engine._start_time if hasattr(engine, '_start_time') else DURATION
log(f"DONE: {elapsed:.0f}s, {added} new, {len(existing)} total, {len(pos)} positive, ${total:.2f}")
