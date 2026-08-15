---
name: shellcode-yara-evasion
description: 恶意代码规避题通用解题 playbook。Use when the challenge is a "对抗规避"/"恶意代码" style target that does NOT want a file upload or a web shell — instead it feeds your submitted shellcode/sample through a detection engine (YARA rules / AV scanner / sandbox) and only gives the flag when your payload EVADES detection. The move is: learn what triggers the detector, then transform the payload (re-encode, split, equivalent-opcode, junk) until it slips through. Do NOT keep submitting the same standard shellcode.
---

# 恶意代码规避题解题 Playbook

## 题型特征:提交 payload,躲过检测器才有 flag

这类题不是让你"上传 webshell 拿 RCE",而是反过来的:**你提交的 shellcode / 样本会被 YARA 规则 / AV 引擎 / 行为沙箱检测**,只有躲过检测才会出 flag(或返回下一步)。先搞清检测器拦什么,再变形。

## 识别检测器

```bash
# 先摸清接口 + 检测器类型
curl -s http://TARGET/            # 看提示:YARA 规则名?AV 引擎?沙箱?
curl -s http://TARGET/rules http://TARGET/openapi.json http://TARGET/help  # 找规则/hint 端点
# 提交一个标准 payload 看被拦的原因(规则名/特征字节)
curl -s -X POST http://TARGET/ -H "Content-Type: application/json" -d '{"payload":"..."}'
```

- 返回"detected / blocked / rule:XXX"→ 是 YARA/AV 规则,规则名会暴露检测的是什么特征。
- 返回"detonation / timeout / behavior"→ 是行为沙箱,躲的是运行行为。

## 规避手法(按命中率)

| 手法 | 针对 | 怎么做 |
|---|---|---|
| **重编码** | 特征字节检测 | 把 shellcode XOR/加减编码,前面加一段自解码 stub,特征字节不再明文出现 |
| **等价指令替换** | 特征 opcode 序列 | `xor eax,eax` 换 `sub eax,eax`;`push 0x68732f` 换分段 push 再拼接 `/bin/sh` |
| **拆分/花指令(junk)** | 特征字符串/长字节串 | 在关键字节间插 nop 或无用指令,打断规则匹配的连续字节 |
| **字符串拼接** | `/bin/sh`、`cmd.exe` 等字面量 | 运行时用 push/栈拼接出字符串,别让完整字符串在代码里出现 |
| **免杀编码器** | AV 静态特征 | msfvenom 换 encoder(shikata_ga_nai),或自定义 XOR 循环 |
| **行为规避** | 沙箱行为 | 加环境检测(检查用户名/域/CPU/延时)让沙箱不触发真实行为 |

## 流程

```bash
# 1. 提交标准 shellcode → 拿到被拦规则/特征
# 2. 定位触发特征(规则名 / 报错里的字节 / 常见特征:/bin/sh、syscall 号、xor 序列)
# 3. 变形:编码 + 自解码 stub,或等价指令替换 + 插花
# 4. 再提交 → 过了就出 flag
```

## 纪律

- **别反复提交同一份 shellcode**:检测器是确定性的,同一份 payload 提交 N 次还是被拦,只是浪费时间。每次提交都要改一点(编码/替换/插花)。
- **规则名就是线索**:如果响应里给了规则名(如 `shellcode_execve`、`yara:reverse_tcp`),直接针对那个特征改,别瞎试。
- **先查有没有规则/hint 端点**:`/rules`、`/help`、`/openapi.json` 常直接泄露检测规则,拿到规则就能精确构造绕过。
- **特征字节是最常见的拦点**:`/bin/sh`、`execve` 的 syscall 号(59/0x3b)、`0x68732f6e69622f` 这类 push 序列,优先处理这些。
