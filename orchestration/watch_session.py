#!/usr/bin/env python3
"""TSecBench run watchdog (v2): detects a stalled scoring session by watching
message_count growth (NOT event timestamps — the events API returns oldest-first,
which caused false stalls). Restarts scoring when the count is flat for STALL_SEC.

Usage: python3 watch_session.py [session_id] [stall_seconds]
"""
import json, sys, time, os, subprocess
import urllib.request as u

BASE = "http://127.0.0.1:8000"
STALL_SEC = int(sys.argv[2]) if len(sys.argv) > 2 else 600
SID = sys.argv[1] if len(sys.argv) > 1 else None

def post(path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    r = u.Request(BASE + path, data=data, method="POST")
    r.add_header("Content-Type", "application/json")
    if token: r.add_header("X-Z3r0-Access-Token", token)
    try:
        with u.urlopen(r, timeout=30) as x: return json.loads(x.read().decode())
    except Exception as e:
        return {"_err": str(e)}

def get(path, token):
    r = u.Request(BASE + path)
    r.add_header("X-Z3r0-Access-Token", token)
    try:
        with u.urlopen(r, timeout=30) as x: return json.loads(x.read().decode())
    except Exception as e:
        return {"_err": str(e)}

def login():
    r = post("/api/system-users/login", {"email": "admin@z3r0.local", "password": "admin123"})
    return r.get("data", {}).get("token")

def session_state(sid, token):
    """Return (is_running, message_count) for a session, or (None, None)."""
    r = get("/api/agent-sessions?limit=50", token)
    d = r.get("data", r)
    items = d.get("items", d) if isinstance(d, dict) else d
    if isinstance(items, dict):
        return None, None
    for s in items:
        if s.get("session_id") == sid:
            return s.get("is_running"), s.get("message_count", 0)
    return None, None

def cancel_session(sid, token):
    return post(f"/api/agent-sessions/{sid}/cancel-all", {}, token)

def restart_scoring():
    print("[watchdog] relaunching score_launch.py ...", flush=True)
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", "/app")
    env.setdefault("Z3R0_LOCAL_EXEC", "1")
    p = subprocess.run(["python3", "/score_launch.py"], env=env,
                       capture_output=True, text=True, timeout=180)
    print("[watchdog] score_launch stdout:", p.stdout.strip()[-300:], flush=True)
    if p.stderr.strip():
        print("[watchdog] stderr:", p.stderr.strip()[-300:], flush=True)

def find_new_sid(old_sid, token):
    """After restart, find the newest running session that isn't the old one."""
    r = get("/api/agent-sessions?limit=50", token)
    d = r.get("data", r)
    items = d.get("items", d) if isinstance(d, dict) else d
    if isinstance(items, dict):
        return None
    running = [s for s in items if s.get("is_running") and s.get("session_id") != old_sid]
    if not running:
        return None
    running.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return running[0].get("session_id")

def main():
    global SID
    token = login()
    if not token:
        print("[watchdog] login failed"); return
    if not SID:
        try:
            SID = open("/tmp/score_sid.txt").read().strip()
        except Exception:
            print("[watchdog] no session id; pass as arg"); return
    print(f"[watchdog] watching session {SID}, stall threshold {STALL_SEC}s", flush=True)
    last_count = None
    last_change = time.time()
    restarts = 0
    while True:
        running, count = session_state(SID, token)
        if count is None:
            print("[watchdog] session not found (ended?). Checking again ...", flush=True)
            time.sleep(60); continue
        if count != last_count:
            if last_count is not None:
                print(f"[watchdog] progress: msgs {last_count} -> {count}", flush=True)
            last_count = count
            last_change = time.time()
        idle = time.time() - last_change
        if idle > STALL_SEC:
            print(f"[watchdog] STALLED (msgs flat for {int(idle)}s). Restarting ...", flush=True)
            cancel_session(SID, token)
            time.sleep(8)
            restart_scoring()
            restarts += 1
            if restarts >= 5:
                print("[watchdog] too many restarts, giving up", flush=True); return
            new = find_new_sid(SID, token)
            if new:
                print(f"[watchdog] now watching {new}", flush=True)
                SID = new
                last_count = None
                last_change = time.time()
        time.sleep(60)

if __name__ == "__main__":
    main()
