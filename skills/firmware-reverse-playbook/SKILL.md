---
name: firmware-reverse-playbook
description: 固件/二进制逆向题通用解题 playbook。Use when the challenge is a "固件逆向"/"逆向" style target: an ELF (often stripped, PIE) that takes a license key/password/serial and prints the flag only on the correct input. These are "reverse the check algorithm, then derive the ONE input that passes". The move is: strings→identify algorithm→dynamic dump (gdb) over hand-tracing→reimplement→self-verify locally before submitting. Do NOT guess/brute-force blindly, and do NOT submit without local verification.
---

# 固件/二进制逆向题解题 Playbook

## 题型特征:给一个 ELF,输入 key/password 对了才出 flag

这类题给一个(常是 stripped + PIE 的)ELF,`argv[1]` 是 license key/password/serial,校验通过才打印 flag。flag 藏在**校验通过后的解密/打印路径**里。要反出"唯一能通过的输入",不是猜。

## 五步走

### 1. 先线索:string + ltrace,别急着啃反汇编

```bash
file ./bin; checksec ./bin                 # 保护:stripped/PIE/静态
strings ./bin | grep -iE "license|key|flag|accepted|denied|seed|usage"
ltrace ./bin AAAAAA 2>&1 | tail            # 看它拿输入做了什么(strcmp?memcmp?长度?)
./bin AAAAAA                                # 跑一次看行为
```

- `strings` 里的 `seed`、`key`、`"License accepted"`、隐藏命令、flag 前缀,都是定位校验函数的锚点。
- `ltrace` 能瞬间看出:输入跟谁 `strcmp`(直接秒)、还是进了自定义变换(要逆向)。

### 2. 识别算法类型(决定后面怎么解)

| 特征 | 算法 | 解法 |
|---|---|---|
| `sbox`/`xorMix`/`keySchedule`/`rotr` 符号,或 256 字节置换表 | RC4 / 自定义流加密 | 手写 Python 翻译 KSA+PRGA,或直接跑原函数解密 ciphertext |
| 状态转移表 + `(state*4+byte&3)` 索引 | 状态机(16×4 表) | 精确翻译表驱动逻辑,或 gdb dump 关键 buffer |
| `magic=0x9e3779b9`(黄金比例) | TEA/XTEA | 已知算法,直接套解密脚本 |
| `0x811c9dc5`/`0x01000193` 常数 | FNV hash | 反推/暴力枚举短输入满足 hash |
| 开头一段自改码 / `memcpy` 到栈再 `call` | 自解密打包 | 先恢复密码/密钥 → 解密出真实代码再分析 |
| Go 二进制(`go:buildid`、`runtime.main`) | Go | 用符号表(`go tool nm`/ghidra 的 Go 插件)定位 `main.validate` 等函数 |

### 3. 动态 dump 优先:别跟复杂变换死磕手推

```bash
gdb ./bin
starti; info proc mappings            # 拿 PIE base
b *0x555555554000+0x136c             # 在"校验完/解密完"的关键点下断
run AAAAAA
x/40bx $rsp+0x10                      # dump 变换结果 / ciphertext / 目标 buffer
```

- 手推状态机/变换容易算错(偏移、表位置、循环语义),**gdb 直接 dump ground truth** 快一个数量级。
- PIE 下地址 = base + 静态偏移,`starti` 后先 `info proc mappings` 拿 base。

### 4. 反解:从校验逻辑推出唯一输入

- **反向**:校验 = `transform(input) == target`,把 target 反着走一遍 transform 得 input(对称算法如 XOR/RC4 可逆)。
- **正向建模**:写 Python 精确翻译算法,再用 z3/暴力枚举求满足 `== target` 的输入。
- **直接跑原函数**:把 binary 当 oracle,用它的解密函数解出 flag(不用自己重写)。

### 5. 本地自验证 → 提交

```bash
./bin "<derived_input>"    # 必须真的打印出 flag 才提交
```

## 高频陷阱(这轮实战踩过的)

- **fallback 字符串不是 flag**:二进制里常有一串 XOR 加密的"假 flag"是 `fopen` 失败时的兜底;真正的 flag 在服务器文件里,要通过 `/check` 端点用正确 key 才返回。别把嵌入式字符串当答案提交。
- **rodata 误读**:dump 数据前先确认是 `.rodata` 还是 `.text`(0x2320+ 可能是代码不是数据表),用 `objdump -s -j .rodata` 精确按节取,别按裸地址猜。
- **多层嵌套**:很多题是"先过一个简单 check(如 key==固定串)→ 再用 key 解密出 flag",别停在第一层就以为解完了,继续看第二层解密逻辑。
- **stripped 无符号**:没有 `main` 符号,用 `__libc_start_main` 的第一个参数定位 main,或从 entry 跟进去。

## 纪律

- **禁止盲猜 flag 提交**:反出的输入先本地喂回验证(`./bin` 真打印 flag)再提交,单题提交 ≤2 次。
- **动态优先于手推**:遇到复杂状态机/变换,先 gdb dump 结果,别陷入手算。
- **先识别算法再动手**:RC4/XTEA/FNV/状态机/自解密各有标准解法,认出来直接套,别从零逆。
