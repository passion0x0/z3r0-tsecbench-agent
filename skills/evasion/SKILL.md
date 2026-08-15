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

## 4. CTF 对抗规避题通法（检测绕过通用方法论）

在 CTF/靶场中，"对抗规避"题往往是：**上传一段 payload（shellcode/恶意代码/脚本），平台有一个检测器（YARA/WAF/沙箱/子串匹配），你必须让 payload 不触发检测但依然能执行。**

### 4.1 第一步：确认检测机制（最重要）

| 检测类型 | 测试方法 | 特征 |
|---|---|---|
| **子串匹配（大小写不敏感）** | 提交含关键词→触发、删关键词→不触发 | 最简单，换等价写法即可 |
| **正则匹配** | 插空格/换行/编码后仍触发 | 需结构改写 |
| **AST/语法树分析** | 等价表达式仍触发 | 需完全重构逻辑 |
| **行为沙箱** | 静态无恶意但动态触发 | 需延迟/条件执行 |
| **YARA 规则** | 规则名暴露了匹配特征 | 按规则名反推匹配串 |

**确认手法**：提交一个"最小触发样本"和一个"最小不触发样本"，二分定位到底检测的是什么（哪个字节/哪个函数名/哪个模式）。

### 4.2 第二步：系统生成绕过族（按检测类型）

**子串/正则检测 → 7 个绕过维度（逐一尝试，不要只试 1-2 个）：**

1. **等价指令替换**：`xor eax, eax` → `sub eax, eax` / `push 0; pop eax`
2. **字符串拼接/运行时构造**：`"/bin/sh"` → `chr(47)+chr(98)+...` / XOR 解密
3. **编码变形**：base64 / hex / rot13 包裹，运行时解码执行
4. **插花/垃圾字节**：在连续特征字节间插 NOP / dead code，打断签名匹配
5. **大小写/Unicode 等价**：`CreateProcess` → Unicode 混淆 / 宽字符
6. **分段传输**：把 payload 拆成多片分别传入，运行时拼接
7. **自解码 stub**：整体加密，前面放一段解密 stub

**行为/沙箱检测 → 3 个绕过维度：**

1. **延迟执行**：sleep / 计时循环 / 等待用户交互后再执行恶意部分
2. **环境检测**：检查非沙箱特征（进程数/磁盘大小/注册表）再执行
3. **多阶段**：第一阶段无恶意行为，C2 回连后才下发恶意指令

### 4.3 铁律

- **确认机制后必须系统生成绕过族**（上面 7+3 个维度逐一试），不要只试一两个就说"exhausted"。
- **二分迭代**：每次只改一个维度，观察是否脱离检测；成功后叠加下一个。
- **最终验证**：绕过后的 payload 必须实际执行成功（不只是绕过检测），否则意义为零。
