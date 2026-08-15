name: graphql-attack
description: GraphQL attack — introspection (schema discovery), IDOR via object args, batching as a force multiplier, hidden/admin fields, and hidden-parameter discovery. Use when a target exposes /graphql or a GraphQL endpoint.
---

# GraphQL Attack

Authorized CTF/assessment use. GraphQL gives you a machine-readable SCHEMA of everything the API can do — if introspection is on, you get the map for free, then attack the authorization gaps and hidden fields.

## 1. Introspection (dump the schema first)

```graphql
query { __typename }
query { __schema { types { name fields { name } } } }
query { __type(name: "User") { fields { name type { name } } } }
```
Introspection lists every type + field, including admin-only ones. If it's blocked:
- error-based discovery (probe field names, read the error suggestions)
- `__type(name:"...")` known-type probes
- extract the schema from the frontend JS bundle / Apollo cache.

## 2. High-value tests

| Theme | Example |
|---|---|
| IDOR | `user(id: "victim")` / `user(id: 1)` → read another user's object |
| batching | send an ARRAY of operations (`[{query...},{query...}]`) → bypass rate limits / authz on the second |
| hidden fields | admin-only fields exposed in the schema (e.g. `users { email passwordHash role }`) |
| nested authz | related-object fields (`user.posts.secret`) with weaker checks than the root |
| mutations | `mutation { deleteUser(id: 1) }` / `updateRole(id:1, role:"admin")` reachable without admin |

## 3. Hidden parameter / field discovery

- Fields present in the schema but not in the UI (admin/internal fields).
- Frontend code uses richer bodies than the visible controls → replay them.
- Permissive schemas accepting extra variables (`role`, `org`, `feature-flag`, internal filters).

## 4. Flow

1. `/graphql` (or `/graphiql`, `/api/graphql`) → introspection query → full schema.
2. Grep the schema for `admin`, `role`, `secret`, `flag`, `user`, `token`.
3. Query those fields directly (IDOR the IDs), batch operations, try mutations.

## Cross-cutting
- **Introspection is the gift** — the schema IS the API documentation; attack it, don't fuzz blindly.
- **Batching + IDOR = the two big wins** — arrays bypass limits, object args bypass authorization.
- Self-verify: a field you shouldn't access returns data (another user's object / an admin field) before claiming the bug.
