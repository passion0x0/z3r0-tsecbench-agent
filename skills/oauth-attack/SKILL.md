name: oauth-attack
description: OAuth 2.0 / OIDC attack playbook — redirect_uri bypass, missing/weak state (CSRF), authorization-code interception, token/secret leakage via Referer, scope escalation, and PKCE bypass. Use when a target uses OAuth/OIDC login (Google/GitHub/custom IdP).
---

# OAuth 2.0 / OIDC Attack

Authorized CTF/assessment use. OAuth bugs are in the FLOW, not the crypto: the `redirect_uri` check, the `state` param, and code/token handling. The win is hijacking another user's authorization code → their account (and the flag behind it).

## 1. redirect_uri bypass (the #1 bug)

The `redirect_uri` decides where the authorization code is sent. Bypass a strict check:
```
https://app.com/callback          (exact-match registration)
https://app.com/callback.evil.com → code sent to evil.com (suffix/prefix match)
https://app.com/callback/../../evil   (path traversal)
https://app.com/callback?next=evil    (param confusion)
https://app.com@evil.com              (host parsing diff)
https://app.com.evil.com/callback     (subdomain not owned)
```
If the code lands at YOUR server, exchange it for the victim's token → account takeover.

## 2. state / CSRF on the OAuth flow

- **Missing `state`:** link your account to the attacker's OAuth account → login CSRF. Craft `https://app.com/oauth/callback?code=ATTACKER_CODE`, send the victim → they log into YOUR account, and their actions/secrets flow to you.
- **Weak/static state:** same, if the value is predictable.

## 3. Code/token interception & leakage

- **Authorization code reuse / not single-use:** reuse a captured code.
- **Referer leak:** the code in a URL leaks to third parties via `Referer` when the page loads external resources.
- **Client secret in source:** grep the frontend/JS/repo for `client_secret` — with it + a captured code you can mint tokens directly.

## 4. Scope & account confusion

- **Scope escalation:** request more scopes than granted (`scope=openid%20admin`) and see if the IdP honors unrequested/extra scopes.
- **Account mapping:** OAuth binds by email only → register an account with the victim's email on the IdP, or find an unverified-email path.
- **PKCE bypass:** if `code_challenge` is present but not verified server-side, drop it / reuse it.

## 5. Flow to test

1. Capture a full OAuth login (authorize → redirect → callback → token).
2. Replay/alter: change `redirect_uri`, drop `state`, swap the code, add scopes.
3. Watch where the code/token lands and whose account you land in.

## Cross-cutting
- **The flow is the attack surface** — `redirect_uri` + `state` + code handling are where 90% of OAuth bugs live.
- **Missing state = login CSRF**, the most overlooked OAuth issue — test it even when redirect_uri looks solid.
- Self-verify: confirm the code/token reached your listener or that you landed in the victim's account.
