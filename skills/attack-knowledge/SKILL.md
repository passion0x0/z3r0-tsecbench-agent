name: attack-knowledge
description: Transferable, principle-level attack knowledge distilled from real solved challenges — NOT specific payloads. Each entry explains the underlying mechanism (why the vuln exists), a systematic method to find and exploit it (how to approach any target of this class), and the variation space (how the same class shows up differently). Use this to derive a solution for a NEW target whose details differ, not to look up a canned payload.
---

# Attack Knowledge (principles, not payloads)

Authorized CTF/assessment use. This is the "teach you to fish" layer: the mechanism + method + variation space for each vulnerability class. A real target will differ in every concrete detail (file names, parameters, filters, binaries) — the principle below still applies, and the method tells you how to adapt.

## 1. File-read / Path Traversal / LFI

**Why it exists:** the program concatenates user input into a filesystem path without normalizing it or checking permissions. Any parameter that names a file (download, preview, include, avatar, template, lang, page) is a candidate.

**Systematic method:**
1. Identify every parameter that resolves to a file. Test with a sentinel and observe (does it echo file content? error with path?).
2. Establish the base directory. Read the SOURCE (the file-read vuln itself often lets you read its own source) or use error messages to learn the include base. The source is the map — it tells you the base dir, the flag location, and any hidden endpoints.
3. Compute the exact traversal depth from base → target (count directories), don't guess one `../` at a time.
4. Enumerate the flag location from a standard list AND from source hints: /flag, /challenge/flag.txt, webroot, /proc/self/environ, config files, DB dumps, app logs.

**Variation space:** filters that strip `../` (try `....//`, `%2e%2e`, double-encoding, absolute paths, `file://`); whitelist path prefixes; apps that append extensions; Windows vs Linux path semantics.

**Key mindset shift:** file-read is a RECON primitive. The flag is rarely the first file you can read — the source/config/creds you extract are the real payload.

## 2. LFI → RCE (the escalation)

**Why:** reading files is limited; executing code wins. Including a path whose content YOU control is code execution.

**Systematic method (pick the reachable one):**
1. Wrapper/protocol injection: `data:`, `php://filter`, `php://input`, `expect://` — include a wrapper whose payload is your code.
2. Log poisoning: write PHP into a log you control (User-Agent in access.log, error.log), then include that log.
3. Session file injection: control a value stored in the session file, include it.
4. `/proc/self/environ`: control User-Agent (it lands in environ), include environ.

**Filter-bypass thinking (the transferable part):** a filter blocks a SPECIFIC pattern (`://`, `php://`, `..`). Find a semantically identical form the filter doesn't match (omit `//` in `data:text/plain,`, alternate encoding, equivalent wrappers). Read the filter's logic before brute-forcing — most filters block a narrow literal, and the whole space around it is open.

## 3. SQLi and WAF bypass

**Why:** the query is built by string concatenation; the WAF is a pattern matcher on the request, not a parser of the SQL. Bypass = change the surface form without changing the SQL meaning.

**Systematic method:**
1. Fingerprint the WAF: what literal is blocked (`'`? `--`? `or`? spaces?). Send it and read the difference (403 vs normal).
2. Rewrite the payload to keep semantics, change surface: comment variants (`-- ` needs trailing space in MySQL, `#`, `/**/`), case, URL/double encoding, equivalent operators (`||` for `OR`), whitespace substitutes (tab, comment, `+`).
3. Confirm with a boolean/error signal (does the response differ on true vs false condition).

**Variation space:** each DB has its own comment/quirk grammar (MySQL `-- `, MSSQL `--`, PostgreSQL `--`); WAFs differ in normalization order (encode before/after match). Learn the target DB dialect, then choose the bypass.

## 4. Deserialization / sandbox escape

**Why:** deserialization turns attacker-controlled data into an object graph; controlling objects means controlling which methods run. A "safe" allowlist/restricted unpickler only blocks DIRECT references to dangerous things — the object graph still links to them.

**Systematic method:**
1. Identify what the deserializer allows (whitelist of types? sandboxed globals?).
2. From an ALLOWED class, walk the object graph to a dangerous callable: `__mro__` → `object` → `__subclasses__()` (enumerate indices to find `os._wrap_close` / `Popen` / `subprocess`), then `__init__.__globals__['popen']`.
3. Trigger the dangerous callable with your command.

**Variation space:** pickle `__reduce__`, yaml `!!python/object`, Java `readObject` chains, Node `constructor.constructor` — same shape: allowed class → graph traversal → dangerous sink. Learn the magic attributes of the specific runtime, then walk the graph.

## 5. Binary reverse → flag recovery

**Why:** a check/validate function is the "flag judge" — an input that satisfies it makes the program reveal the flag. You don't need to understand the whole binary, only the judge.

**Systematic method:**
1. `file` + `checksec`; locate the check/validate function (strings, symbols, or the code path that prints success/failure).
2. Extract its LOGIC. Two paths:
   a. Reimplement the check in Python from the disassembly (fastest when the algorithm is self-contained), then brute-force/search the input space for "accepted".
   b. If the constraint is complex, use z3/angr to solve symbolically for the satisfying input.
3. On success, the program emits the decoded flag — capture that output.
4. Self-verify locally before submitting.

**Key principle:** reimplementing the judge + brute-forcing the input is usually faster than fully reversing the crypto or fighting a debugger. Reverse the SEMANTICS (what must hold), not every instruction.

## 6. Multi-stage / APT (layered attack surface)

**Why:** real networks are layered; each layer has its own goal and the flag lives deepest. Foothold is the START, not the win.

**The layered model (re-apply at every new position):**
- **Position → recon:** interfaces, routes, hosts (/etc/hosts, ARP, DNS), services, files.
- **Recon → primitive:** file-read, RCE, shell, admin access.
- **Primitive → credentials:** source configs, `.env`, `~/.ssh`, bash_history, DB tables, env vars — every credential is a key to try everywhere (password reuse is the #1 lateral win).
- **Credentials → lateral:** SSH/DB/login into the next host; repeat the loop one hop deeper.
- **Terminal → flag:** the deepest host/DB holds it; read flag_count and keep going until all flags are collected.

**Key principle:** after EVERY new foothold, restart recon. Don't stop at "I can read files" — that's recon toward credentials, and credentials are the bridge to the next layer.

## Cross-cutting meta-rules
1. Match the target to a CLASS (by symptom), then apply the method — never look for an identical challenge.
2. Read the SOURCE/config when you can — it's the map that makes the rest deterministic instead of guesswork.
3. Self-verify locally before submit; verify flag FORMAT.
4. A filter/WAF is a narrow pattern matcher — the space around it is the bypass.
