name: api-security
description: API authorization testing — BOLA (Broken Object Level Authorization, access other users' objects by changing IDs), BFLA (function-level authz), mass assignment, and hidden-field privilege escalation. Use when the target is a JSON REST/GraphQL API with object IDs in paths or bodies.
---

# API Authorization (BOLA / BFLA / Mass Assignment)

Authorized CTF/assessment use. APIs fail on authorization more than authentication: the endpoint trusts the client to stay in its own lane. Change the object ID, swap the token, or add a privilege field — the flag is usually someone else's object.

## 1. The core loop (BOLA)

1. Create Account A and Account B.
2. As A, capture the create/read/update/delete flows for an object.
3. Replay the SAME request with B's token (or with the object ID changed to another user's).
4. If you can read/write another user's object → BOLA confirmed.

**The tell:** predictable IDs in the path — `/api/v1/orders/123`, `/api/v1/users/1/invoices/9`, `/api/v1/files/<uuid>` — try the next/previous ID, another user's ID, or an admin object.

## 2. Test surfaces

| Surface | Example |
|---|---|
| object read | `/api/v1/orders/123` → try `124`, `1` |
| nested object | `/api/v1/users/1/invoices/9` |
| admin/internal fn | `/api/v1/admin/users`, `/internal/...` |
| method abuse | same route via `PUT`/`PATCH`/`DELETE` (weaker authz than `GET`) |
| GraphQL args | `user(id: "victim")`, batching arrays |

## 3. Mass assignment (add the privilege field)

When the API binds a JSON body to a model, add fields the client shouldn't set:
```json
{"username":"me","role":"admin"}
{"isAdmin":true}
{"verified":true}
{"org":"target-company"}
{"tier":"premium","balance":999999}
```
The flag/privilege is often reached by setting a field the UI never exposes.

## 4. What testers miss

- IDs in **headers** (`X-User-Id`), **cookies**, and **nested JSON objects** — not just the URL path.
- Alternate HTTP verbs on the same route.
- Hidden fields in the response echoed back into a later request (client-controlled `role`, `org`, `verified`).
- `additionalProperties`/permissive schemas that silently accept extra fields (mass assignment).

## Cross-cutting
- **Two accounts are the whole trick** — you can't see authorization bugs with one token. Register A + B, diff the access.
- **Try the ID before the exploit** — enumerate neighbors; the flag is often the next object over.
- Self-verify: a 200 + the other user's data (not your own) confirms BOLA.
