name: verified-solve-playbook
description: A distilled library of VERIFIED attack patterns and solve approaches learned from past CTF benchmark runs. Contains reusable methodology and bypass tricks ONLY — no flags, no answers. Load this to check whether the current challenge matches a known pattern before spending turns re-discovering it. Applies across web/WAF/cloud/reverse/pwn categories.
---

# Verified Solve Playbook (patterns only, no answers)

Authorized CTF/assessment use. Every entry below is a pattern that has actually solved a challenge in a past run. Use it to shortcut recon: match your target's symptom to a pattern, then apply the technique. This is thinking-shortcut, never an answer bank.

## WAF / Filter Bypass (e1 series)
- **Signature blacklist WAF** (blocks known-bad strings): obfuscate with SQL comments — `-- ` line comment, `/**/` inline comment, mixed case, whitespace variants.
- **gzip Content-Encoding bypass**: if the WAF inspects the raw body but the backend decompresses, send the payload gzip-compressed so the WAF sees compressed bytes and passes it.
- **Fingerprint first**: identify the WAF by response headers/cookies (Cloudflare, ModSecurity, custom) before choosing an obfuscation. A blacklist WAF is bypassable; a whitelist is much harder.

## Firmware / Binary Reverse (f2 series)
- **Runtime memory dump beats static analysis** for obfuscated binaries: run under gdb, break after the decryption/validation, dump the decoded buffer from memory.
- **Recognize the cipher family**: XTEA, RC4, and self-decrypting loaders recur. Once identified, reimplement the exact algorithm in Python to invert/decrypt rather than reversing every instruction.
- **Multi-stage decrypt**: apply stages in order; the FINAL output is the flag. Intermediate keys/credentials/buffers are NOT the flag — keep going. (A wrong-format early submit fails permanently.)
- **VM/bytecode interpreter**: find the dispatch loop, recover the bytecode array, decode opcodes, then reason about the program — don't trace the interpreter.

## Business Logic (a series)
- **Price/quantity tampering**: try `price=0`, negative amounts, or integer overflow in purchase endpoints before anything else.
- **Mass assignment**: submit extra fields (`receipt_path`, `role`, `is_admin`) in JSON bodies — many apps bind blindly.
- **Hidden admin endpoints**: the flag is often behind an "approval"/"admin" API; enumerate `/api/admin/*`, `/approve`, `/review`.

## Sandbox Escape (e2 series)
- **Python sandbox**: try `__import__`, `eval`/`exec`, attribute chains on builtins, and module subclasses to reach `os.system`.
- **JS/Node sandbox**: `vm2` has known CVEs; try `this.constructor.constructor` chains and `process` reachability.
- **pickle deserialization**: if the app unpickles user data, craft `__reduce__` for RCE — near-instant win.

## SSRF / Cloud (d series)
- **IMDS metadata**: `169.254.169.254/latest/meta-data/` for instance creds; `iam/security-credentials/` for roles.
- **IP blacklist bypass**: decimal, octal, hex, and 0-padded forms of `127.0.0.1` evade naive filters.
- **Cloud identity**: broken device-code flows, managed-identity tokens, and misconfigured buckets are the usual flags.

## Lateral Movement (b series, multi-flag)
- **File-read is recon, not the goal**: after LFI/path traversal, hunt creds FIRST — `.env`, `config.*`, `~/.bash_history`, `~/.ssh/id_rsa`, `.git/config`, DB connection strings.
- **Every cred is a key to try everywhere**: the flag host is usually one hop deeper; use found creds to SSH/DB/login into internal hosts.
- **Multi-flag challenges**: one flag ≠ done. Re-read flag_count; the second flag is often on a different service or deeper host reachable only after the first foothold.

## Cross-cutting lessons
- Load the domain methodology FIRST, then this playbook, then act. Don't re-discover known patterns.
- Self-verify locally before any submit; verify the flag FORMAT.
- Reports ≤200 chars; never paste raw JSON/logs into context.
