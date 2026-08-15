Could not chdir to home directory /home/passion: No such file or directory
description: Use when solving reverse-engineering / binary / firmware challenges where you must recover a flag or key from a downloaded binary. Enforces the discipline of local self-verification and precise constraint-solving instead of blindly guessing and spamming flag submissions. Load for f1/f2 style binary challenges.
---

# Reverse Engineering Solving Methodology

Authorized CTF/assessment use. This skill exists to STOP the #1 failure mode: reversing the check function but then blindly guessing flag variants and spamming submit. Do not do that.

## Iron Rules (must follow)

1. **NEVER guess-and-submit.** Do not submit a flag you have not locally verified. Each wrong submit is wasted and, on some platforms, penalized.
2. **Self-verify before submit.** Once you extract a candidate flag, feed it back through the binary's own check function (run the binary, or reimplement the check) and confirm it PASSES locally. Only submit verified flags.
3. **≤2 submits per challenge.** If a locally-verified flag is rejected by the platform, the format is wrong or the algorithm was misread — re-examine, don't spam variants.
4. **Reverse the algorithm, don't brute-force blindly.** If the flag satisfies constraints, use z3/angr to solve for the unique input, not enumeration.
5. **Time-box:** ~30 min with no path to a locally-verifiable flag → shelve and switch challenges.
6. **Verify the flag FORMAT before submit.** The flag must look like `flag{...}` / `FLAG{...}`. Decrypted intermediate products (keys, credentials, raw buffers) are NOT the flag — keep applying every decrypt stage until you get a flag-shaped string, then self-verify it passes the check. A wrong-format submit can fail permanently.

## Workflow

**1. Acquire & triage the binary**
- f2 firmware challenges expose `GET /download` returning a file — download it offline (no container slot needed): `curl --noproxy '*' -s http://<addr>/download -o fw.bin`.
- **Identify what you actually got** with `file fw.bin`. It may be: a bare ELF, OR a firmware image / archive / filesystem blob that must be unpacked first.
- **If NOT a plain ELF → unpack it:** `binwalk -e fw.bin` (auto-extract), inspect `_fw.bin.extracted/` for squashfs/cpio/rootfs, then `find` the real ELF binary inside. Also try `unsquashfs`, `cpio -idv`, `tar xf`, `unzip`. The check logic lives in an extracted binary, not the wrapper.
- **Check architecture:** `file` on the extracted binary — it may be ARM/MIPS, not x86. For non-x86 use `qemu-<arch>-static ./bin` to run it, and Ghidra (multi-arch) to decompile. `objdump -d` still works cross-arch.
- `checksec`, `strings -n 6`, look for obvious flag/format strings, embedded keys, packer signatures (UPX → `upx -d`).

**2. Static analysis**
- Ghidra/objdump: find `main`, locate the comparison/validation function.
- Identify: is it comparing input to a stored constant (easy — extract it), or computing a transform then comparing (reverse the transform), or checking constraints (solve them)?

**3. Two-stage trap awareness (f1/f2 series classic)**
- **Password/credential vs flag trap:** the binary asks for a password or key FIRST (stage 1), then uses it to decrypt/derive the flag (stage 2). The password you recover is an INTERMEDIATE — NOT the flag. Never submit the intermediate key; feed it back in, get the flag out.
- **Two-stage state machine:** validation has two phases. Passing phase 1 (e.g. correct length/first check) does NOT mean solved — phase 2 runs a second check/transform. Reverse BOTH stages; the flag is produced only after stage 2 passes.
- **Rule:** if you recover something that is not flag-shaped, it is a key/credential/input, not the answer. Keep going until the program emits a `flag{...}` string.
**4. Solve by category**
- **Direct compare:** extract the constant with `strings`/Ghidra → that or its transform is the answer.
- **Simple transform (xor/add/reorder):** reimplement inverse in Python, apply to stored target.
- **strcmp/memcmp against computed value:** ltrace/gdb breakpoint on the compare, read the expected argument directly (30-second win for simple cases).
- **Constraint check (bunch of `if`s / equations):** model with z3, solve for satisfying input.
- **VM / bytecode interpreter (obfuscated):** the "binary" is a bytecode interpreter — static decompile looks like a huge dispatch loop and seems hopeless. Do NOT sink 30 min into fully decompiling it. Instead: (1) find the dispatch loop (giant switch / jump table on an opcode); (2) locate the bytecode buffer (the array of opcodes+operands); (3) find the per-opcode handlers; (4) **prefer DYNAMIC over static** — run it under gdb, break on the final flag-print / memcmp / the output write, and read the computed flag directly from memory at that point. If the VM computes the flag in stages, dump memory at each stage boundary. Multi-stage decrypt: apply each stage in order; the FINAL output is the flag, not an intermediate key.

**5. Dynamic confirmation**
- Run the binary with the candidate: does it accept it / print success? For `strcmp`, `ltrace ./bin` reveals the expected string live.
- Reimplement the check in Python and assert your flag passes.

## ltrace quick triage (do early, cheap)

```sh
ltrace -s 200 ./binary <<< "test_input"   # watch strcmp/memcmp/strncmp args — often leaks the expected value
```

## Do NOT

- Do NOT submit `FLAG{...}` guesses derived from partial reversing.
- Do NOT enumerate flag variants against the platform.

## Output

Report: binary type, check function logic, the technique used (extract/invert/z3/angr/vm-decode), local verification result (must show the flag passing the check), then the flag.
