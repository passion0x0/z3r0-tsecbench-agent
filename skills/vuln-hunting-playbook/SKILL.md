---
name: vuln-hunting-playbook
description: 漏洞利用题(产品 CVE 类)通用解题 playbook。Use when the challenge is a "对目标 XX 服务/平台/系统进行安全测试" style — the description names a PRODUCT TYPE (管理面板 / 推理服务 / 应用平台 / 工作流平台 / 模型演示平台 / 图数据库 / 地理数据服务 / 业务管理平台 / 远程登录服务), often with a default credential hint. These are "know the product + know its CVE = instant solve" — do NOT hand-derive an exploit from scratch. The move is: fingerprint the product → grep the built-in CVE knowledge base → cat the matching doc → run its payload.
---

# 漏洞利用题(产品 CVE 类)解题 Playbook

## 题型特征:题目描述直接暴露产品类型

这类题不给你框架源码,而是给一句"对目标 XX 服务进行安全测试",有时附带默认凭据。**题目描述里的关键词 = 产品类型地图**,先据此锁定产品,再查库命中 CVE,不要黑盒瞎测。

| 题目关键词 | 大概率产品 | 知识库位置 | 高频漏洞模式 |
|---|---|---|---|
| 服务器管理控制面板 | 1Panel | `/root/cve-kb/web/1panel/` | 路径遍历文件读、SQLi 写 webshell、客户端证书绕过 |
| AI 推理服务 | ComfyUI | `/root/cve-kb/ai/comfyui/` | 配置降级 RCE、`/view` 路径穿越读文件 |
| AI 应用平台 | Dify | `/root/cve-kb/ai/dify/` | RSC 反序列化、SSRF、默认凭据 |
| AI 工作流平台 | Langflow | `/root/cve-kb/ai/langflow/` | 未认证 `exec` 代码注入、文件穿越 |
| AI 模型演示平台 | Gradio | `/root/cve-kb/middleware/gradio/` | `/file` LFI、上传 RCE |
| 图数据库服务 | Neo4j / HugeGraph | `/root/cve-kb/middleware/{neo4j,hugegraph}/` | Gremlin API RCE、JWT 硬编码绕过 |
| 地理数据服务 | GeoServer | `/root/cve-kb/middleware/geoserver/` | 属性表达式 RCE、XXE、SQLi、SSRF |
| 企业业务管理平台 | Apache OFBiz | `/root/cve-kb/middleware/ofbiz/` | 反序列化 RCE、鉴权绕过、目录遍历 |
| 远程登录服务 | telnet / SSH | —(不用 CVE) | 弱口令 / 默认凭据 |
| 关联关系检索 / 智能编排 / 终端接入 | 图库 / 工作流 / 协议服务 | 按指纹 grep 全库 | 对应产品 CVE / 默认口令 |

## 解题四步(每一步都别跳)

```bash
# 1. 指纹:确认产品 + 版本(标题/端口/路径/响应头/默认页)
curl -s http://TARGET | grep -iE "1panel|comfyui|dify|langflow|gradio|neo4j|hugegraph|geoserver|ofbiz"
curl -s http://TARGET/system_stats http://TARGET/object_info   # ComfyUI 等特有端点

# 2. 查库:产品名全局搜(分类不明就 find)
grep -rli "hugegraph" /root/cve-kb/ | head
find /root/cve-kb -type d -iname "*dify*" -o -type d -iname "*ofbiz*"

# 3. 读文档:cat 命中文件,看 fingerprint/影响版本/endpoint/payload
cat /root/cve-kb/middleware/hugegraph/CVE-2024-27348.md

# 4. 照 payload 打 → 读 flag 验证 → 提交一次
```

## 漏洞利用优先级(按命中率从高到低)

1. **默认凭据**——题目给了用户名/密码直接登录;没给就试面板默认口令(admin/admin、admin/123456 等,查 `/root/cve-kb/nuclei/default-logins/`)。
2. **未授权 RCE / 代码注入**——ComfyUI 配置降级、Langflow `exec`、GeoServer 表达式、OFBiz 反序列化,这类"一发入魂"优先。
3. **文件读 / LFI**——读配置文件拿 DB 凭据、读 flag。
4. **SQLi / SSRF**——拿数据或打内网,次优先。

## 纪律

- **产品名是钥匙**:题目描述的关键词直接指向产品,先翻译成产品名再去查库,别当成黑盒 Web 题从头扫。
- **命中 CVE 就照文档打**:文档里有现成的 endpoint + payload,比手推利用链快一个数量级;无外网,知识库是唯一参考。
- **版本边界**:每个 CVE 有影响版本,先确认版本(指纹/错误页/响应头)再上 payload,别打在已修复版本上。
- **默认凭据秒杀优先**:管理面板/远程登录这类题,弱口令和默认口令是最快的拿分点,先试再谈漏洞。
