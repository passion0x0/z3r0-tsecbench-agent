name: saml-sso
description: SAML SSO assertion attack — signature validation bypass, signature wrapping, assertion replay, weak audience/recipient checks, and account mapping via unverified attributes. Use when a target uses enterprise SSO with SAMLRequest/SAMLResponse/ACS endpoints.
---

# SAML SSO Assertion Attack

Authorized CTF/assessment use. SAML trusts an XML assertion the IdP signs; the bugs are in whether the SP verifies that trust. Forge or rewrap the assertion → log in as anyone (admin → flag).

## 1. When to load

- Login flow uses `SAMLRequest`/`SAMLResponse` (base64 XML) and an ACS endpoint.
- You see an external IdP redirect, `AssertionConsumerService`, or `POST`/`Redirect` binding.

## 2. High-value misconfiguration checks

| Theme | What to check |
|---|---|
| signature validation | unsigned assertion accepted? only a child node signed (not the whole assertion)? |
| signature wrapping | move the signed element aside, inject your own unsigned assertion |
| audience / recipient | weak `Audience` / `Recipient` / `Destination` / ACS URL checks |
| issuer trust | wrong IdP accepted, multi-tenant issuer confusion |
| replay / freshness | missing `InResponseTo`, weak `NotBefore`/`NotOnOrAfter` |
| account mapping | binds by email only, case folding, unverified attributes (`uid`, `email`, `role`) |
| XML parser | XXE-ish parser or unsafe transforms around the SAML doc |

## 3. The core attacks

**Unsigned / re-signed assertion:** capture a real `SAMLResponse`, decode the base64 XML, edit `NameID`/`uid`/`role` to `admin`, re-encode, POST to the ACS. If the SP doesn't verify the signature (or only checks one node), you're in.

**Signature wrapping (XSW):** the SP validates the FIRST `Assertion` element but processes the LAST. Keep the real signed assertion, append your forged `<Assertion>` after it — the SP reads yours, the signature check passes on the first.

**Attribute/role forging:** the assertion's `Attribute` elements (`role`, `groups`, `isAdmin`) drive authorization — change them. If account binding is email-only and you control an email, register that email on the IdP.

**Replay:** re-use a valid-but-expired assertion if `NotOnOrAfter` isn't enforced.

## 4. Quick triage

1. Capture one full login round trip (SAMLRequest → IdP → SAMLResponse → ACS).
2. Decode the response (`base64 -d`, gunzip if deflated) and inspect which XML nodes are signed and which attributes drive identity/role.
3. Test: strip the signature, edit attributes, wrap a forged assertion, replay — one at a time.
4. Watch the resulting session (who you logged in as).

## Cross-cutting
- **Trust = signature + audience + freshness** — attack whichever of the three the SP skips.
- **Decode before you attack** — the assertion is base64 (+ maybe deflated) XML; read it first.
- Self-verify: the ACS returns a session for the forged identity (admin) before claiming bypass.
