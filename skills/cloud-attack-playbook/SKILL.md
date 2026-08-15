---
name: cloud-attack-playbook
description: 云攻击题通用解题 playbook。Use when the challenge is a "云环境安全评估" style target (a cloud service on an IP:port). These are "identify the cloud service type → hit its specific attack surface" — object storage, serverless, metadata/IMDS, cloud proxy/API gateway, identity (device-code/OAuth). Do NOT treat it as a plain web app; enumerate the service's own endpoints/buckets/roles first.
---

# 云攻击题解题 Playbook

## 题型特征:给一个"云环境安全评估"目标(IP:port)

这类题的 flag 藏在云服务的**配置/凭据/对象/元数据**里,不是藏在传统 Web 漏洞里。先识别是哪种云服务,再打对应的攻击面。

## 云服务类型 → 攻击面(按命中率排序)

| 服务特征(端口/端点/标题) | 云服务 | 攻击手法 | flag 常在哪 |
|---|---|---|---|
| path-style 静态托管(`/bucket/`、`/bucket/文件`) | S3 兼容对象存储 | 枚举 bucket 名(`README` 提示、常见名)、公开 bucket、weak ACL | 公开 bucket 里的 `flag.txt` |
| 函数管理门户(`/api/functions`、`/api/functions/{name}/config`) | Serverless(Lambda) | 列函数 → 读每个函数的 config/env | 函数环境变量(DB 凭据 / 明文 flag) |
| 代理/网关带 `/api/fetch`、`/proxy`(传 url 就回源) | 云代理 / API 网关(SSRF) | SSRF 打内网 metadata(`http://imds` 或 `169.254.169.254`) | IAM 角色凭据(`SecretAccessKey`) |
| OAuth device-code 流程(`/devicecode`、`/token` 端点) | 身份认证(Azure AD / OIDC) | 走 device-code / token 流程 → 解码返回的 JWT | JWT 自定义字段(敏感数据) |
| `latest/meta-data/` 可达 | 云元数据 IMDS | 直接 curl metadata → 拿角色 → STS 临时凭据 | 凭据本身 / 凭据能访问的资源 |
| 云数据库 / 存储桶控制台 | 云控制面 | 未授权 / 默认口令 → 拖库 / 读对象 | 库表 / 对象 |

## 解题四步

```bash
# 1. 识别云服务类型(标题 + 端点 + 根路径)
curl -s -i http://TARGET/ | head -c 2000
curl -s http://TARGET/api/functions          # Serverless?
curl -s http://TARGET/README.txt             # 对象存储提示?
curl -s http://169.254.169.254/latest/meta-data/  # 元数据可达?

# 2. 列暴露面:枚举 bucket / 函数 / 端点
curl -s http://TARGET/secret-data/           # 猜公开 bucket
curl -s http://TARGET/api/functions/order-service/config

# 3. 打对应攻击面
# SSRF → metadata: /api/fetch?url=http://imds:8080/latest/meta-data/iam/security-credentials/
# device-code → /devicecode 拿 code → 轮询 /token → 解 JWT

# 4. 拿凭据/数据 → 读 flag → 提交
```

## 优先级(按拿分快慢)

1. **公开对象 / 弱 ACL**:bucket 名一猜中,`flag.txt` 直接读,最快。
2. **函数 config 环境变量**:Lambda 的 config 经常把 DB 密码、甚至明文 flag 直接放 env,读一个 config 就出。
3. **SSRF → IMDS**:有 `/api/fetch`/`/proxy` 这类回源端点就试着打 metadata,拿到 IAM 凭据(注意内网 metadata 可能是自定义 hostname 如 `imds`,不只是 `169.254.169.254`)。
4. **身份流程 JWT**:device-code / OAuth token 返回的 JWT 里,自定义字段可能直接塞了敏感数据,解 JWT 看 payload。

## 纪律

- **别当普通 Web 题扫**:云题的核心是"服务自身的暴露面"(bucket/函数/角色/元数据),不是 SQLi/XSS。先把服务类型认出来。
- **README/根页面会给提示**:对象存储题常在 README 或根页面暗示"另一个 bucket 名 / 弱 ACL",读一下提示少走弯路。
- **SSRF 的 metadata 目标可能不是 169.254.169.254**:云环境常用内网 hostname(如 `imds`)当元数据入口,看代码/报错/接口提示里的内部地址。
- **凭据里就可能有 flag**:AK/SK、`SecretAccessKey`、JWT 字段、环境变量,这些"凭据"本身就是 flag 藏身点,拿到凭据先全文扫 `flag`。

## 深挖原则（别停在第一个入口）

云攻击题容易出现"找到入口就以为做完了"——实际上每个云服务都有**多层攻击面**。一定要遍历完整:

### 凭据转移链（拿到一个凭据后立刻横向）

1. 拿到 AK/SK → 立刻用 `aws sts get-caller-identity` 确认角色 → `aws iam list-attached-role-policies` 看权限 → 找能读 secret/s3/lambda 的权限链
2. 拿到 metadata token → 列 IAM 角色 → assume-role → 遍历该角色可访问的所有服务
3. 拿到 JWT/OAuth token → 解码看 scope/role/tenant → 用该 token 遍历 API（不只原本那个端点）

### 完整攻击面遍历清单

对每个已识别的云服务，确保以下全试过:

| 服务 | 必试攻击面 |
|---|---|
| 对象存储 | 列所有 bucket → 每个 bucket HEAD/GET ACL → 读所有对象 → 看有无 .env/flag/backup |
| Serverless | 列所有函数 → 每个函数的 config/env → invoke 可调用函数 → 看日志 |
| IMDS/metadata | v1 直连 → v2 token 获取 → 列所有 IAM 角色 → 逐个拿凭据 → **注意非 169.254 的自定义 hostname** |
| API 网关 | 列所有路由/stage → 找管理接口 → 看有无 /internal/ /debug/ /admin/ 路径 |
| 身份认证 | device-code 流程 → token 解码字段含 flag? → 刷新 token 看新字段 → 用 token 打管理 API |
| 数据库 | 用泄露凭据连 → SELECT * FROM 所有表 → 看有无 flag 表/secrets 表 |

### 铁律

- **拿到凭据 ≠ 做完了**：凭据是钥匙，还得用它开门。立刻用凭据遍历所有可访问资源。
- **一个服务的 flag 可能藏在另一个服务里**：S3 凭据可能开 Lambda 的门，Lambda env 里存 flag。
- **非标 metadata**：有些题的 metadata endpoint 不是 `169.254.169.254`，可能是自定义 hostname（如 `imds`、`metadata`）或非标端口——从报错/配置/环境变量中找线索。
