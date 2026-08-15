name: evasion
description: Antivirus/EDR evasion — the 7 technique families to make a payload/shellcode/loader undetected: API hashing, string obfuscation (XOR), memory permission flipping, direct/indirect syscalls, anti-analysis, AMSI/ETW patching, and ntdll unhooking. Use when a payload is flagged or the target has AV/EDR that blocks your tooling.
---

# AV/EDR Evasion

Authorized CTF/assessment use. Evasion = change the payload so static signatures and runtime hooks don't catch it. Seven technique families; stack them (one alone is rarely enough).

## 1. The 7 families

| Family | Goal | Technique |
|---|---|---|
| api_obfuscation | hide API imports | API hashing, IAT obfuscation |
| string_obfuscation | hide sensitive strings | XOR-encrypt strings, decrypt at runtime |
| memory_evasion | avoid RWX pages | allocate RW → write → flip to RX |
| execution_evasion | bypass userland hooks | direct syscalls, indirect syscalls |
| anti_analysis | detect debugger/sandbox | IsDebuggerPresent, timing, CPU count |
| amsi_etw_bypass | disable AMSI/ETW | patch AmsiScanBuffer / EtwEventWrite |
| unhooking | restore hooked DLLs | remap a clean ntdll |

## 2. The essentials

**AMSI bypass (PowerShell/.NET payloads):**
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
**ETW patch (silence .NET logging):** patch `EtwEventWrite` to `ret`.

**String obfuscation (the #1 static-detection killer):**
```python
# XOR a string, decrypt in the loader at runtime
key = 0x41
enc = bytes(c ^ key for c in b"cmd.exe /c ...")
# in loader: ''.join(chr(b ^ 0x41) for b in enc)
```

**Direct syscall (bypass ntdll hooks):** instead of calling `NtAllocateVirtualMemory` through the hooked ntdll export, issue the syscall number directly (or re-map a clean ntdll and call through it).

**Memory permission flip:** allocate with `VirtualAlloc` (RW), write the shellcode, then `VirtualProtect` to RX — never RWX (which AV flags instantly).

## 3. Workflow

1. Identify WHY it's detected: static signature (strings/imports) vs runtime (hook/AMSI).
2. Apply the matching family: strings → obfuscation; imports → hashing; hook → syscall/unhook; AMSI → patch.
3. Re-test (upload to the target / run in the environment) — iterate until clean.
4. Stack: an undetected loader usually needs string obfuscation + one execution-evasion + anti-analysis.

## Cross-cutting
- **Diagnose before evading** — is it the string signature, the import table, or the runtime hook? Each has a different fix.
- **One technique is not enough** — combine string obfuscation with syscalls/unhooking and memory flipping.
- Self-verify: the payload actually RUNS (not just compiles) after evasion — a clean-but-broken payload is useless.
