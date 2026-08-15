name: request-smuggling
description: HTTP request smuggling / desync — exploit CL.TE / TE.CL / TE.TE interpretation mismatches between a front-end proxy and back-end server to smuggle a hidden request, bypass access controls, or poison the queue. Covers detection, the canonical payloads, and HTTP/2 downgrade desync. Use when a target sits behind a reverse proxy/load balancer/CDN.
---

# HTTP Request Smuggling (Desync)

Authorized CTF/assessment use. Smuggling = the front-end and back-end disagree on where one request ends, so you prepend a hidden request that the back-end runs against the NEXT connection. The wins: reach blocked paths (admin), bypass WAF, hijack other users' requests.

## 1. The three classic mismatches

- **CL.TE** — front-end honors `Content-Length`, back-end honors `Transfer-Encoding: chunked`.
- **TE.CL** — front-end honors `Transfer-Encoding`, back-end honors `Content-Length`.
- **TE.TE** — both honor TE but handle malformed TE headers differently (obfuscate the TE header so one side ignores it).

## 2. Canonical payloads

**CL.TE** (smuggle a `GET /admin`):
```
POST / HTTP/1.1
Host: target
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```
Front-end reads CL=30 (one request); back-end reads chunked `0` (end) then treats `GET /admin` as the next request.

**TE.CL** (smuggle via a non-chunked-looking body):
```
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

12
GET /admin HTTP/1.1
0

```
Front-end (TE) reads the chunked body; back-end (CL=4) stops after `12\r\n`, leaving `GET /admin` as the next request.

**TE.TE obfuscation** (make one side ignore the TE header):
```
Transfer-Encoding: xchunked        (one side drops it, falls back to CL)
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
```

## 3. Detection

1. Send a request whose smuggled part is a benign `GET /404page` or a path with a distinct response.
2. Send a NORMAL request immediately after on the same connection.
3. If the second request's response is the smuggled path's response → desync confirmed.
4. Time-based variant: smuggled `POST /` with an incomplete body makes the next request hang (front-end waits for bytes) → measurable delay = CL.TE.

## 4. What to do with it

- **Bypass access control:** smuggle `GET /admin` (the back-end runs it without the front-end's ACL).
- **Bypass WAF:** the WAF only inspects the first (legitimate-looking) request.
- **Queue poisoning / request hijacking:** smuggle a partial request so the next victim's real request is appended to it and their response/cookie leaks to you.
- **HTTP/2 → HTTP/1 downgrade desync** (H2.CL / H2.TE): the same mismatch across the protocol boundary behind CDNs; use the `:authority` vs `Host` and CL/TE conflicts.

## Cross-cutting
- **Only meaningful behind a proxy/CDN** — a single-server app has no desync to exploit. Fingerprint the stack first.
- **CL.TE is the highest-hit in CTFs** — try it first, then TE.CL, then TE.TE.
- Self-verify with a distinct smuggled path before escalating to admin bypass or hijack.
