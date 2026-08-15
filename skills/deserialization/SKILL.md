name: deserialization
description: Insecure deserialization across languages — recognize the serialized format (PHP O:, Java ac ed/rO0, .NET AAEAAAD, Python pickle, Node _$$ND_FUNC$$_), find the sink, and exploit with the right gadget chain (ysoserial, PHP pop chains, Node IIFE). Use when a cookie/token/body is an opaque blob that gets deserialized, or source shows unserialize/readObject/pickle.loads.
---

# Insecure Deserialization (cross-language)

Authorized CTF/assessment use. If the app deserializes data you control, you can usually get RCE or auth bypass — the trick is (1) recognizing the format, (2) knowing the right gadget for the runtime. Deserialization runs BEFORE app validation, so a crafted payload bypasses normal checks.

## 1. Recognize the format (fingerprint the blob)

| Language | Tell |
|---|---|
| PHP | `O:<len>:"Class":...` (often base64) or `phar://` archive |
| Java | raw hex `ac ed 00 05`, or base64 starting `rO0`; also XStream/XMLDecoder |
| .NET | base64 `AAEAAAD/////` (BinaryFormatter/SoapFormatter) |
| Python | pickle opcodes; or `yaml.load` without SafeLoader |
| Node | `{"_$$ND_FUNC$$_...` (node-serialize / serialize-javascript) |
| Ruby | `Marshal.load` / `YAML.load` without safe_load |

Where to look: cookies, headers, hidden form fields, JWT-adjacent tokens, file uploads, message queues, DB-stored user content.

## 2. Exploit by runtime

**PHP (`unserialize`, `phar://`):** build a POP chain — a magic-method gadget (`__destruct`/`__wakeup`/`__toString`) that calls a sink (`system`, `file_get_contents`, `include`). Look for gadget classes in the app/known frameworks; or `phar://` to trigger unserialize on file operations.

**Java (`ObjectInputStream.readObject`):** use **ysoserial** — pick the gadget matching the classpath (CommonsCollections, CommonsBeanutils, Spring, Groovy, ...), generate the serialized payload, send it. This is the same primitive behind Shiro/Fastjson/WebLogic chains — the gadget depends on which libs are present.

**Python (`pickle.loads`):** trivial RCE via `__reduce__`:
```python
import pickle, os, base64
class E:
    def __reduce__(self): return (os.system, ('cat /flag',))
print(base64.b64encode(pickle.dumps(E())))
```
`yaml.load` → `!!python/object/apply:os.system ["cat /flag"]`.

**Node (node-serialize):** IIFE RCE:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami');}()"}
```

**Golang/Rust/Ruby:** gob `interface{}` type confusion; `Marshal.load` / `YAML.load` gadget chains.

## 3. Blind / black-box approach

1. Spot an opaque blob (cookie/token) and the endpoint that consumes it.
2. Mutate a byte → does the response change / error leak a class name? (confirms deserialization + reveals stack)
3. If Java, test ysoserial gadgets one-by-one (a sleep/DNS gadget as the canary); if PHP, hunt for a POP chain in source; if Python, the `__reduce__` payload is universal.
4. Escalate the canary to `cat /flag`.

## Cross-cutting
- **Fingerprint first** (the format decides the entire attack) — a hex `ac ed` blob and a base64 `rO0` blob are both Java, but `O:` is PHP and needs a totally different chain.
- **Gadget availability is version/classpath-dependent** — when one chain fails, switch gadgets/libraries, not the concept.
- Self-verify with a benign canary (sleep / DNS / `id`) before the flag read.
