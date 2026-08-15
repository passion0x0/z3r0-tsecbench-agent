name: captcha-bypass
description: Techniques to bypass login CAPTCHA/verification codes. The key insight: most CTF captchas are a logic flaw (fixed value, reusable, client-side only, or a captcha-free backend API), not a real OCR problem. Logic bypass first, OCR last. Targets the OA/login captcha stall.
---

# CAPTCHA Bypass

Authorized CTF/assessment use. A captcha on a login form is usually the WEAKEST gate — most challenges implement it with a logic flaw. Bypass the LOGIC first; only fall back to OCR when the captcha is genuinely enforced server-side and changes every attempt.

## 1. Logic bypasses (try these FIRST — most CTF captchas fall here)

**A. Captcha value is fixed / in the response:**
- Inspect the login response HTML: the captcha answer is often in a hidden field, a cookie, the image filename, or a comment (`<input type=hidden name=code value="...">`).
- The same captcha may accept a constant (e.g. always `1234`, `0000`) — try the obvious fixed values.

**B. Captcha is client-side only:**
- The form checks the captcha in JS but the backend never validates it → submit with ANY/empty captcha, or bypass JS entirely and POST directly.

**C. Captcha is reusable / not invalidated:**
- Solve once (or get one valid code), then REPLAY the same captcha+session across requests. If the session keeps the captcha valid, you get unlimited attempts.

**D. Empty / omitted captcha param:**
- Drop the `captcha`/`code`/`verify` field entirely, or send it empty. A common bug: backend only checks captcha if the field is present.

**E. Captcha regenerates but old one still valid:**
- The new image replaces the old, but the server still accepts the previous session's captcha → reuse the first one.

## 2. OCR (only when server-side + changes every attempt)

**Image captcha (4-6 chars, no noise):**
```bash
# tesseract
tesseract captcha.png out -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyz
# ddddocr (much better on noisy/deformed captchas)
python3 -c "import ddddocr;print(ddddocr.DdddOcr().classification(open('captcha.png','rb').read()))"
```
Preprocess with ImageMagick first when noisy: `convert captcha.png -colorspace Gray -threshold 60% -resize 200% out.png`.

**Math captcha ("3+5=?"):** OCR the digits, or grep the expression from the response (the equation is usually printed as text next to the image).

**Slider / drag captcha:** these are rarely the real gate — check for a `token`/`ticket` endpoint you can call directly (see #3).

## 3. Go around the captcha entirely

The captcha guards the LOGIN FORM. The backend API behind it is often captcha-free:
- **Call the login/submit API directly** (the endpoint the form posts to), skipping the captcha page. The API may accept the request without the captcha field.
- **Use another auth path:** SSO, password-reset, API-token, `/api/login`, mobile endpoints (`/mobile/login`) often lack captcha.
- **Session/cookie reuse:** if you already have ANY valid session (from an earlier stage), reuse it to reach the admin area without logging in.
- **The OA cheat-code:** OA systems expose RCE/SQLi/datasource endpoints (see oa-system-attack skill) that let you read the DB directly — the user table holds accounts/hashes, so you never touch the captcha.

## 4. When you must interact (server-side, changing, no API)
1. Fetch the captcha image + session cookie in ONE request.
2. OCR it (ddddocr).
3. Submit code + same session cookie immediately (before expiry).
4. On failure, re-fetch (new image+session) and retry — never reuse the stale session.

## Cross-cutting
- **Logic first, OCR last.** 80% of CTF captchas are fixed/reusable/client-side/omittable — check those in minutes before installing OCR.
- **The captcha protects a FORM; the API/DB behind it usually doesn't.** Route around the form.
- **Self-verify:** a successful login (200 + new session) or a direct API 200 is the confirmation — then proceed to the flag.
