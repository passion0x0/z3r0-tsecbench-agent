name: race-condition
description: Race condition (TOCTOU) exploitation — find a timing window where two concurrent requests both pass a check (redeem twice, rate-limit bypass, double-spend, coupon reuse, TOCTOU on file/balance), then widen the window with single-packet/last-byte sync and fire parallel requests. Use on redeem/apply/purchase/upload endpoints that should be allowed only once.
---

# Race Condition (TOCTOU) Attack Playbook

Authorized CTF/assessment use. A race condition = two requests both pass a "check" before either "use" completes, so a once-only action happens twice. Find the once-only feature, then make many requests arrive in the SAME instant.

## 1. Spot the race-prone feature

Anything "allowed once but not twice":
- Redeem coupon / voucher / invite code (use twice)
- Apply a discount / balance transfer / withdraw (double-spend)
- Rate-limit or brute-force lockout (bypass the counter)
- File upload with "delete after process" (TOCTOU read)
- Password reset / email change (overwrite race)
- Vote / like / register (double-count)

## 2. Widen the window (make the race winnable)

The check→use gap is tiny; make the requests land together:
- **Same connection + same packet:** send both requests in one TCP packet (Burp "single-packet attack").
- **Last-byte sync (Turbo Intruder):** hold back the final byte of each request, release all of them simultaneously so the server starts processing N requests at once.
- **Pre-compute everything** (tokens, headers, body) so the requests are identical and fast.
- **Many threads × many attempts** — a 1% race wins over 1000 attempts.

## 3. Fire & verify

1. Capture the once-only request (e.g. `POST /redeem code=X`).
2. Build 20-50 identical copies, single-packet/last-byte sync them.
3. Check the result: did the balance apply twice? did the code redeem twice? (compare a counter/balance before vs after).
4. If yes → race confirmed → exploit the impact (double-spend to reach flag / bypass a limit).

## 4. Common patterns

- **TOCTOU on files:** upload a file, and between the check (valid) and use (execute/read), swap it for a malicious one (symlink swap).
- **Rate-limit bypass:** fire N login attempts in one packet — the counter increments after each, but if they're processed before the counter check, all pass.
- **Double-spend:** two concurrent "spend" requests both read the old balance, both subtract once → net negative.

## Cross-cutting
- **Concurrency is the weapon** — single-packet + last-byte sync beats naive "send many requests fast".
- **The window is small but real** — a persistent race over many attempts eventually wins.
- Self-verify by a measurable state change (balance/count/flag) that should be impossible under correct locking.
