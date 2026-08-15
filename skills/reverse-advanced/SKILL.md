name: reverse-advanced
description: Advanced reverse engineering — anti-debug/anti-analysis bypass, packer identification + unpacking, language/platform recognition (Python bytecode, .NET, WASM, Go, Rust), and the toolchain (Ghidra/radare2/angr/qiling/Frida). Use on obfuscated/packed/virtualized binaries where plain disassembly stalls.
---

# Advanced Reverse Engineering

Authorized CTF/assessment use. When the binary resists plain disassembly (packed, anti-debug, unusual language), the work is: (1) recognize what you're actually looking at, (2) strip the protection, (3) get back to normal reversing. These are the un-blockers.

## 1. Recognize the language / platform FIRST

| Tell | Language | Approach |
|---|---|---|
| `.pyc` / "python" strings | Python bytecode | `pycdc` / `uncompyle6` / `decompyle3` |
| `mscoree` / IL metadata | .NET | `dnSpy` / `ILSpy` / `monodis` — full decompile |
| `.wasm` magic | WASM | `wasm2wat` / `wasm-decompile` |
| huge binary, no libc imports, Go strings | Go | `go_parser` / recover symbols (`GoReSym`) |
| Rust panic strings, mangled symbols | Rust | demangle (`rustfilt`) |
| packed/UPX signature | packed | see §2 unpack |

## 2. Packer / protection handling

```bash
file bin            # "UPX" → upx -d bin
# detect: high entropy sections, few imports, small .text
strings bin | grep -i "upx\|pack\|protect"
```
- **UPX:** `upx -d bin` (or `upx -d` with the right version if it fails).
- **Custom packer:** dump the process AFTER it unpacks in memory (gdb `dump memory` at OEP, or a tool like `Scylla`/`pe_unmapper`), then fix the IAT.
- **Virtualized (VMProtect/Themida):** don't fight the VM — use dynamic tracing (see §4) or attack the VM's handler table.

## 3. Anti-debug / anti-analysis bypass

Common checks to find and patch/hook:
```
ptrace(PTRACE_TRACEME)     → LD_PRELOAD a stub, or patch the check
IsDebuggerPresent / PEB BeingDebugged   → patch / hook
timing checks (rdtsc)       → patch the comparison
"/proc/self/status" TracerPid → hook the read
```
- **Linux:** `strace` to see the anti-debug syscalls; `gdb` + breakpoint on the check, flip the branch.
- **Windows:** `ScyllaHide` / `x64dbg` anti-anti-debug plugins.
- **Frida** (cross-platform): hook the check function and return the "clean" value.

## 4. The dynamic/emulation toolchain

```
angr   → symbolic execution: find the path to "flag correct", solve constraints
qiling → emulate the binary (run a firmware/WASM/full binary without the real device)
gdb + pwndbg/gef   → break on the flag-print / memcmp, read memory
Frida  → hook functions, bypass checks, dump decrypted blobs
dogbolt.org / Ghidra / radare2 + r2ghidra → multi-decompiler cross-check
```

## 5. Unblock workflow

1. `file` + `strings` → recognize the language/format (not x86 ELF → see §1).
2. If packed → unpack (upx/dump-at-OEP).
3. If anti-debug → neutralize it (patch/hook) so the debugger works.
4. Then reverse normally (find the check, reimplement/solve — see reverse-solving-methodology).

## Cross-cutting
- **Recognition unblocks everything** — a `.pyc`/`.NET`/`WASM`/Go binary has a faster path than "disassemble x86".
- **When a packer/VM is present, go DYNAMIC** — dump the unpacked process or trace the VM, don't static-decompile the protector.
- Self-verify: after unpacking/bypass, you can actually reach the check function and read the logic.
