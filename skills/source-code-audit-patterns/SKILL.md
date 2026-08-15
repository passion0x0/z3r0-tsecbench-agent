---
name: source-code-audit-patterns
description: 代码审计越权/漏洞 pattern 速查。Use when the challenge gives you source code (Go/Python/Java/Node) and asks you to find access control flaws, privilege escalation, or auth bypass. Covers the most common patterns that lead to vulnerabilities in each language.
---

# 代码审计越权 Pattern 速查

## 通用审计三步法

1. **找鉴权中间件/装饰器** → 看哪些路由**没挂**它
2. **找对象 ID 来源** → 是从 session/JWT 取还是从请求参数取(参数=可篡改)
3. **找权限检查** → 是 `role == "admin"` 还是 `user_id == resource.owner_id`(缺后者=越权)

## Go 代码审计 Pattern

### 越权(最常见)

```go
// 危险: user_id 从请求参数取,不从 JWT/session 取
func GetProfile(c *gin.Context) {
    userID := c.Param("id")  // ← 可篡改! 改成别人的 ID 就越权
    user := db.FindUser(userID)
    c.JSON(200, user)
}

// 修复版: 从 JWT 取(不可篡改)
func GetProfile(c *gin.Context) {
    userID := c.GetString("jwt_user_id")  // ← 从中间件注入
}
```

**审计搜索**: `c.Param\|c.Query\|c.PostForm\|r.URL.Query` → 看这些取出来的 ID 有没有和当前用户比对

### 路由未挂鉴权

```go
// 危险: admin 路由组忘记加 AuthMiddleware
r.GET("/admin/users", listUsers)        // ← 任何人都能访问!
r.GET("/admin/tokens", getAdminToken)   // ← 直接拿 admin token!

// 安全版:
admin := r.Group("/admin", AuthMiddleware(), RequireRole("admin"))
```

**审计搜索**: 找所有 `r.GET\|r.POST\|r.Group` → 对比哪些有 middleware 哪些没有

### JWT/Token 缺陷

```go
// 危险: 只验签不验 role/claims
claims := parseJWT(token)  // 验签通过
// 但没检查 claims.Role == "admin" 就放行了 admin 路由
```

## Python 代码审计 Pattern

### Flask/Django 越权

```python
# 危险: @login_required 只验证"已登录",不验证"是否有权限访问该资源"
@app.route('/api/users/<int:user_id>/secret')
@login_required
def get_secret(user_id):
    return User.query.get(user_id).secret  # ← 任何已登录用户都能看别人的 secret

# 修复: 加 ownership 检查
    if user_id != current_user.id:
        abort(403)
```

**审计搜索**: `request.args\|request.form\|request.json` 取的 ID → 有没有和 `current_user` / `session['user_id']` 比对

### 装饰器遗漏

```python
# 危险: 新加的路由忘了加 @admin_required
@app.route('/admin/export_all_data')  # ← 没有 @admin_required!
def export_all():
    return jsonify(db.get_all_secrets())
```

## Java/Spring 代码审计 Pattern

### @PreAuthorize 遗漏

```java
// 危险: Controller 方法没有 @PreAuthorize
@GetMapping("/api/admin/tokens")
public ResponseEntity<?> getTokens() {  // ← 任何人都能调
    return ResponseEntity.ok(tokenService.getAll());
}
```

**审计搜索**: 找所有 `@GetMapping\|@PostMapping` → 看有没有 `@PreAuthorize\|@Secured\|@RolesAllowed`

### SpEL 表达式注入

```java
// 危险: 用户输入拼进 SpEL
@Value("#{${user_input}}")  // ← RCE!
```

## Node.js 代码审计 Pattern

### Express 中间件遗漏

```javascript
// 危险: 路由定义在 authMiddleware 之前
app.get('/api/secret', getSecret);       // ← 没鉴权!
app.use(authMiddleware);                 // ← 中间件在后面,不生效
app.get('/api/profile', getProfile);     // ← 这个有鉴权
```

### 原型链污染

```javascript
// 危险: merge/deep-copy 用户输入到对象
_.merge(config, req.body);  // req.body 含 __proto__.isAdmin = true → 污染全局
```

## 审计速查命令

```bash
# Go: 找未鉴权路由
grep -rn "r\.GET\|r\.POST\|r\.PUT\|r\.DELETE" . | grep -v "Middleware\|Auth\|Login\|Register"
# Go: 找参数取 ID
grep -rn "c\.Param\|c\.Query" . | grep -i "id\|user\|admin\|token"

# Python: 找未加装饰器的路由
grep -rn "@app.route" . | grep -v "login_required\|admin_required\|permission"

# Java: 找无鉴权 Controller
grep -rn "@GetMapping\|@PostMapping" . | grep -v "PreAuthorize\|Secured"

# Node: 找路由定义顺序问题
grep -n "app\.\(get\|post\|use\)" .
```

## 铁律

- **找到一个越权点就够** — 不需要审完全部代码
- **先搜 admin/secret/token/key 相关路由** — 高价值目标优先
- **参数来源 = 漏洞本质**: 从 URL/body 取的可篡改,从 session/JWT 取的不可篡改
