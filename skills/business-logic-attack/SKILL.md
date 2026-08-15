---
name: business-logic-attack
description: Web 业务逻辑漏洞解题通法。Use for challenges about payment bypass, race conditions, price manipulation, signature forgery, access control bypass, privilege escalation, and multi-tenant isolation break. Covers the full spectrum of logic bugs that don't rely on injection but on flawed business assumptions.
---

# Web 业务逻辑漏洞通法

## 题型识别 → 攻击手法速查

| 题面关键词 | 漏洞类型 | 攻击手法 |
|---|---|---|
| "支付/下单/余额/价格" | **支付逻辑** | 修改金额/数量为负/0、并发下单(条件竞争)、先下单再改价、积分/优惠券叠加溢出 |
| "签名/回调/异步通知" | **签名伪造** | 找签名算法(HMAC/MD5)→ 构造合法签名 → 伪造支付成功回调 |
| "抽奖/概率/isSolved" | **前端逻辑绕过** | 直接调后端 API 设置状态 / 修改请求参数 / 条件竞争重放 |
| "越权/隔离/租户" | **水平越权** | 替换 user_id/tenant_id/object_id → 访问别人的数据 |
| "管理员/运维令牌/admin" | **垂直越权** | 找权限检查缺陷(role 字段可控 / JWT claim 篡改 / 路径绕过鉴权) |
| "PoW/防刷/线程安全" | **条件竞争** | 并发请求在检查与执行之间插入(TOCTOU) |
| "deploy key/secret/密钥" | **信息泄露→越权** | 找泄露点(.git/env/config/debug端点) → 用泄露的凭据访问受保护资源 |
| "初始密码/默认口令" | **弱凭据** | 枚举用户+试初始密码(工号/手机号/123456/公司名) |

## 通用解题流程

### 1. 理解业务流(不要直接扫)

```
注册/登录 → 找到"关键动作"(购买/转账/授权/导出) → 抓完整请求链 → 理解参数含义
```

### 2. 四个必试攻击面

**A. 参数篡改:**
- 价格/数量改为 0、-1、超大数
- user_id/role/权限字段改为 admin/其他用户
- 对象 ID 遍历（IDOR）

**B. 条件竞争:**
```bash
# 同一个请求并发 10 次(余额只扣一次但执行多次)
for i in $(seq 1 10); do
  curl -s -X POST http://target/api/buy -d '{"item":"flag","qty":1}' -H "Cookie: sess=xxx" &
done
wait
```

**C. 流程跳跃:**
- 跳过支付直接调"确认收货"
- 跳过验证直接调"修改密码"
- 先获取订单号再伪造回调

**D. 签名伪造:**
```python
# 找到签名算法后本地构造
import hmac, hashlib
key = b"从源码/配置泄露的key"
msg = b"order_id=xxx&amount=0&status=paid"
sig = hmac.new(key, msg, hashlib.md5).hexdigest()
# 用这个 sig 调回调接口
```

### 3. 代码审计题加速

给了源码(Go/Python/Java)的越权题:
- 直接搜 `isAdmin\|role\|permission\|authorize\|middleware` 找鉴权逻辑
- 找 `route\|handler\|endpoint` 看哪些路由没挂鉴权中间件
- 找 `user_id\|tenant\|org_id` 看是否从 JWT/session 取还是从请求参数取(参数取=可篡改)

## 铁律

- **先理解正常业务流,再找逻辑缺陷。** 盲注入扫描对逻辑题完全无效。
- **每个"数量/金额"字段都试负数和零。**
- **每个"对象 ID"字段都试遍历。**
- **支付类题必试条件竞争。**
- 题面说"签名伪造"→ 一定有签名密钥泄露点,先找泄露再构造。

## IDOR (越权对象访问) 速查

### ID 类型与预测

| ID 模式 | 示例 | 攻击方式 |
|---|---|---|
| 顺序整数 | id=1001 | 直接 ±1 遍历 |
| UUID v4 | 550e8400-... | 从自己的响应/其他接口收集别人的 UUID |
| UUID v1 | 时间序列 UUID | 时间可预测,提取 timestamp |
| Base64 编码 | eyJpZCI6MX0= | 解码→改→重编码 |
| Hash(id) | md5("1001") | 猜测原始 ID 后计算 hash |
| 复合 ID | /users/1/orders/5 | 两个 ID 都可独立篡改 |

### 测试方法

1. 创建两个账号 A 和 B
2. 用 A 执行所有操作,记录所有出现的对象 ID
3. 用 B 的 session 访问 A 的对象 ID → 成功=IDOR
4. 别忘了 **HTTP 方法枚举**: GET 被拦时试 POST/PUT/PATCH/DELETE(鉴权可能只写了 GET)
5. **参数污染**: `id[]=1234&id[]=5678`(数组), `{"id":"1234","id":"5678"}`(JSON 重复 key)

## 条件竞争精华(CTF 实战打法)

### 必试场景

| 操作 | 为什么有竞争 |
|---|---|
| 优惠券/兑换码使用 | check "未使用" → mark "已使用" 不是原子的 |
| 余额扣款/转账 | check "余额够" → 扣款 之间有窗口 |
| 投票/点赞限制 | check "未投过" → 记录投票 |
| 注册唯一性 | check "用户名不存在" → 插入 |
| 限时抢购/库存 | check "有库存" → 减库存 |

### 并发打法(无 Burp,纯 curl)

```bash
# 方法 1: bash 后台并发(最简单)
for i in $(seq 1 20); do
  curl -s -X POST http://target/api/redeem \
    -H "Cookie: session=xxx" \
    -d '{"code":"COUPON123"}' &
done
wait
# 看有没有多次 success

# 方法 2: HTTP/1.1 pipeline (更精准)
# 用 python requests + ThreadPoolExecutor
python3 -c "
import requests, concurrent.futures
url='http://target/api/buy'
headers={'Cookie':'session=xxx'}
data={'item':'flag','qty':1}
with concurrent.futures.ThreadPoolExecutor(20) as e:
    fs=[e.submit(requests.post,url,json=data,headers=headers) for _ in range(20)]
    for f in concurrent.futures.as_completed(fs):
        r=f.result(); print(r.status_code, r.text[:100])
"
```

### 关键技巧
- **网络延迟 ≈ 竞争窗口**: 靶场容器在同一网段(10.0.x.x),延迟极低,更容易命中
- **并发数 20-50 通常够**,不需要上千
- **看返回**: 正常只该 1 次 success,如果出现 2+ 次 = 竞争成功
- **有些题需要先"预热"**(创建订单) 再并发"确认"(付款/兑换)
