name: binary-vuln-discovery-methodology
description: Use when you must FIND the vulnerability in a binary (before exploiting it) — source audit or black-box binary analysis. Covers the full discovery pipeline: recon (identify protections/architecture/input surface), static analysis (Ghidra/objdump hunt for dangerous patterns), dynamic confirmation (gdb/cyclic/ASAN), fuzzing (crash-driven discovery), and bug classification with a primitives summary handed to the exploitation phase. Pairs with pwn-methodology (exploit) and reverse-solving-methodology (flag recovery).
---

# Binary Vulnerability Discovery Methodology

Authorized CTF/assessment use. The job here is **finding and proving the bug**; exploitation is pwn-methodology's job. Deliverable: bug class, exact trigger, offset, mitigation state, and the primitive it gives you.

## Iron Rules

1. **Protections first.** `checksec` on the binary AND `file` for arch — they dictate what's even exploitable and what bug classes matter. A hardened binary (PIE+canary+Full RELRO) needs a leak primitive; a no-PIE no-canary one is wide open.
2. **Find the input surface.** Every bug needs an input path. Map: stdin reads (`gets`/`read`/`scanf`), network parse (protocol functions), file parsing (format parsers), env/args. Unreachable code is not a bug.
3. **Prove it, don't assert it.** A "suspicious strcpy" is not a finding until you've crashed it: feed `cyclic`, watch gdb RIP/RSP, confirm the exact overflow offset / the exact format-string index / the exact UAF free-then-use.
4. **Classify into primitives.** The output must be usable by the exploit phase: stack overflow @ offset N (RIP control) / format string @ arg k (leak+write) / heap UAF (arbitrary write) / OOB read (info leak).
5. **Time-box ~20 min static, ~15 min dynamic per target.** If the bug isn't obvious fast, fuzz or move on — don't reverse the whole binary looking for it.

## Workflow

### Phase 1 — Recon (2 min)
- `file ./binary` (arch, static/dynamic), `checksec --file=./binary` (NX/PIE/canary/RELRO), `strings -n 6` (debug symbols, format strings, `win`/`system`/`/bin/sh`, hints).
- Determine input surface: run it, see prompts; `strings` for "Input"/"Password"; `nm -D` for imported funcs (`gets`, `printf`, `read`, `system`, `strcpy`, `sprintf`, `memcpy`, `malloc`, `free`).
- Note: `checksec` in newer pwn tools prints mitigations table — read it carefully.

### Phase 2 — Static analysis (Ghidra/objdump)
- Find `main` → trace the input-handling call chain. For each input sink, ask: **is the buffer big enough? is the length checked?**
- **Dangerous patterns checklist:**
  - `gets(buf)` / unbounded `read(fd, buf, n)` with n > buf → **stack overflow**
  - `sprintf(dst, fmt, ...)` / `strcpy` / `strcat` without length → **overflow**
  - `printf(user_input)` / `fprintf(f, user_input)` → **format string**
  - `malloc(size_from_input)` then write fixed size → **heap overflow**
  - `free(p)` then use `p` → **UAF**
  - `arr[user_index]` without bounds check → **OOB / arbitrary r/w**
  - off-by-one in a loop (`<=` vs `<`) → **off-by-one** (overwrite RBP LSB → stack pivot)
- For network parsers: find the protocol handler, map each field → its sink.

### Phase 3 — Dynamic confirmation (gdb / cyclic / ASAN)
- **Stack overflow:** `cyclic(200) > in.txt` → `gdb -batch -ex 'run < in.txt' -ex 'info registers'` → `cyclic_find(0x...rsp/rip value)` → exact offset. Confirm you control RIP.
- **Format string:** `python3 -c "print('%p.%p.%p.%p.%p.%p.%p')"` → run → count `(nil)`/`0x` positions to find your input offset; `AAAA.%6$p` style to pin it.
- **OOB/heap:** run under ASAN if available (`gcc -fsanitize=address` won't apply to provided binary; use gdb watchpoints instead, or feed oversized input and watch crash site).
- **Off-by-one:** feed exact-size input + 1 byte, see if saved RBP's low byte changes.

### Phase 4 — Fuzzing (if static isn't revealing)
- Quick win: `python3 -c "print('A'*N)"` sweep N = 64,128,256,512,1024 for crash threshold; then `cyclic` for exact offset.
- Structured fuzz: if the parser takes complex input, `radamsa`/`afl-fuzz`-style mutation on a valid sample, watch for crashes. (Tools may be limited in container — manual mutation + gdb is often faster for CTF-size binaries.)

### Phase 5 — Classify & hand off
Deliver to the exploitation phase (pwn-methodology):
```
Binary: ./chall (x86-64, dynamic, no PIE, no canary, NX on)
Bug: stack overflow in read() → 136 bytes into 64-byte buf
Primitive: RIP control @ offset 136
Mitigations: NX on → ret2libc; no PIE → known addresses; RELRO partial → GOT writable
Win path: system@plt present → ret2libc or ret2win
```

## Protection identification quick table
| checksec line | Meaning | Implication |
|---|---|---|
| NX enabled | stack not executable | need ROP / ret2libc, not shellcode |
| PIE enabled | binary randomized | need a code-base leak first |
| Canary found | stack canary on | need canary leak / bypass |
| RELRO Full | GOT read-only | can't overwrite GOT; target hooks/IO |
| RELRO Partial | GOT writable | GOT overwrite viable |

## Do NOT
- Do NOT report a bug without a proven trigger (crash/leak) and exact offset/index.
- Do NOT reverse the entire binary — find the input surface, chase the sinks.
- Do NOT start exploiting before handing off the primitives summary.

## Output
Report: protections (checksec), arch/static-dynamic, input surface, bug class(es) with exact trigger + offset/index, confirmation method (crash/cyclic/gdb), primitives summary, recommended exploit route.
