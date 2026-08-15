---
name: waf-bypass-methodology
description: Use when a web target has a WAF, reverse proxy, API gateway, or input filter in front of the backend and your injection/attack payloads are being blocked. Covers WAF fingerprinting and payload obfuscation techniques to slip SQLi/XSS/command-injection past the filter to reach a vulnerable backend.
---

# WAF / Filter Bypass Methodology

Authorized testing only. Use when the backend is vulnerable but a boundary filter (WAF, reverse proxy, API gateway, custom regex) blocks your payload. The vuln is real; you must reach it.

## Step 1: Confirm and Fingerprint the WAF

- Send an obvious payload (`' OR 1=1`, `<script>`, `; id`) and observe: block page, 403, 406, reset, or altered response.
- Fingerprint by cookies/headers: Cloudflare (`__cf_bm`, `cf_clearance`, `/cdn-cgi/`), Imperva (`X-CDN: Incapsula`), AWS WAF (`AWSALB`), Sucuri (`X-Sucuri-ID`), ModSecurity, NAXSI.
- Determine filter type: signature blacklist (block known-bad) vs whitelist (allow known-good only). Blacklist is bypassable by obfuscation.

## Step 2: Bypass Techniques (try in order)

**Case & encoding**
- Mixed case: `SeLeCt`, `ScRiPt`.
- URL-encode / double URL-encode: `%2527`, `%253C`.
- Unicode / overlong UTF-8, full-width chars (`＜`), homoglyphs — esp. for "multi-language" targets.
- HTML entities, hex, octal.

**SQL-specific**
- Inline comments: `/*!50000SELECT*/`, `SEL/**/ECT`, `UNI/**/ON`.
- Whitespace alternatives: `/**/`, `%09`, `%0a`, `%0c`, `%a0`, parentheses `UNION(SELECT(1))`.
- Keyword splitting via comments, `%00` null bytes.
- Alternate operators: `||`, `&&`, `LIKE`, `RLIKE` instead of `=`/`AND`/`OR`.

**Command-injection-specific**
- Variable insertion: `w'h'o'a'm'i`, `who$@ami`, `who${IFS}ami`.
- `$IFS`, `${IFS}`, `<`, `{cat,/flag}` for space filtering.
- Backslash/quote insertion: `who\ami`, base64: `echo <b64>|base64 -d|sh`.

**HTTP-layer / architecture**
- Change method: GET↔POST, add body params.
- Content-Type switch: `application/json` vs form vs multipart — WAF may only parse one.
- Parameter pollution: `id=1&id=2` — WAF reads first, backend reads last (or vice versa).
- Chunked transfer-encoding, oversized body to exhaust WAF inspection window.
- Extra whitespace/padding before payload; junk parameters to push payload past inspection limit.
- Case of header names, duplicate headers, `X-Forwarded-For`/`X-Original-URL`/`X-Rewrite-URL` to reach protected routes.

**Request smuggling** (reverse proxy / gateway): CL.TE / TE.CL desync to slip a hidden request past the front proxy to the backend. Relevant for "reverse proxy filters requests to backend" style targets.

## Step 3: Systematic Approach

1. Find a payload that triggers the vuln with NO WAF (baseline the backend behavior).
2. Reduce to the minimal blocked token (which exact keyword/char trips the WAF).
3. Apply obfuscations targeting only that token until it passes AND still executes on backend.
4. Confirm backend execution (not just "not blocked").

## Target-class Note

WAF/proxy/gateway challenges are explicitly "a filter in front, backend login/input still vulnerable". Approach: identify backend vuln class (usually SQLi in login or command injection or reflected injection), then apply the matching obfuscation family. Multi-language targets hint at Unicode/encoding bypass.

## Output

Report: WAF identified, backend vuln class, the exact bypass technique that worked, final working payload, and evidence of backend execution.
