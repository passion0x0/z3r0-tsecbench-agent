---
name: tcp-line-protocol-pwn
description: TCP 行协议服务 pwn 题通用解题 playbook。Use when the challenge is a "逆向TCP"/"二进制" style target that is NOT a downloadable ELF but a live TCP service on an IP:port that speaks a line-based text protocol (banner + commands like STORE/CHECK/HEARTBEAT/COPY/SETBODY). These are memory-corruption-in-a-service: the flag lives in the process's memory and leaks via overflow / out-of-bounds write / over-read. Do NOT look for a file to read — the flag is in memory.
---

# TCP 行协议服务 pwn 题解题 Playbook

## 题型特征:活的 TCP 行协议服务(不是下载 ELF)

这类题不给你二进制文件,只给一个 IP:port,连上去先回一个 banner,然后是一套文本命令。**flag 常驻在服务进程的内存里**(一个全局变量/数组/结构体),靠内存破坏把它"顶出来"或"读出来"——不是靠读文件。

## 三步走

### 1. 认服务:banner 别误读

```bash
python3 -c "
import socket
s=socket.socket(); s.settimeout(5)
s.connect(('TARGET',PORT))
print(repr(s.recv(4096)))   # banner 是服务的名字/缩写
"
```

- banner 是**缩写/口号**,别当游戏或谜语:"lrud" = **LRU cache**,"responsd" = **HTTP response builder**。看清英文再判断服务。
- 常见:token store、LRU cache、key-value store、heartbeat 服务、HTTP 构建器、内存数据库。

### 2. 摸协议:发 HELP / 试命令,摸清每个命令干什么

```bash
# 发 HELP,再逐个试命令,记录每个命令的输入/输出/边界
s.sendall(b'HELP\n'); print(s.recv(4096))
```

关键要摸清:
- **存储类**(STORE/SET/ADD/SETBODY):往哪个 buffer 写,写多长,有没有长度检查。
- **读取类**(CHECK/GET/LIST/DUMP/BUILD):从哪个 buffer 读,输出里会不会带相邻内存。
- **长度/偏移类**(HEARTBEAT len / COPY offset):有没有负偏移、越界、长度欺骗。

### 3. 找内存破坏 → 泄露 flag(四种模式)

| 模式 | 怎么触发 | flag 怎么出来 |
|---|---|---|
| **固定 buffer 溢出覆盖相邻变量** | 往固定大小(如 32B)的 buffer 写超长内容,溢出覆盖相邻的 flag 全局变量 | 之后读该变量/列表(`[LAST]`、CHECK)时 flag 被带出 |
| **长度欺骗过读(类 Heartbleed)** | 协议声称返回 N 字节,实际只发回 M 字节,其余是相邻内存 | 把 N 设大,泄漏出来的内存里翻 `flag` |
| **负偏移越界写** | `COPY -1 X` 这类负 offset 被当成无符号/缺下界检查,写到 buffer 外的 guard/计数/flag | 覆盖 guard 或让 flag 变量被改写后经 COUNT/DUMP 输出 |
| **dump 直接泄漏内存** | BUILD/DUMP 类命令把内部结构体(含 flag)原样打印 | 直接 grep `flag` 输出 |

## 纪律

- **flag 在内存,不在文件**:这类题别再找 `/flag.txt`、别找文件读——服务是内存态,flag 是进程里的一个变量/结构体,靠溢出/越界/过读让它泄漏。
- **先摸清边界再打**:每个命令的最大长度、偏移检查(有没有负值检查)、count 上限,先探清楚,别盲目塞超长输入(可能把服务打崩自毁)。
- **一次只改一个变量**:确认溢出目标(是 flag 变量还是 guard)再精确控制长度,别一上来就几千字节把整个内存打乱。
- **读到 flag 立即提交**:泄漏出来的内存里 grep `flag` 拿到完整值就提交,别继续折腾把服务搞崩。
