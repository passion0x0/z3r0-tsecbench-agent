---
name: web-vuln-methodology
description: Use for authorized black-box web application penetration testing methodology — how to systematically find vulnerabilities (not how to run one tool). Covers recon, JS source analysis, threat modeling per feature, and the decision flow for SQLi/IDOR/SSRF/upload/auth-bypass/logic flaws. Load this first when attacking a web target and unsure which vulnerability class to pursue.
---

# Web Vulnerability Hunting Methodology

Authorized testing only. This skill is the *thinking framework* for finding web vulns. Pair it with tool skills (sqlmap, ffuf, nmap) for execution.

## Core Principles

- **Read code before testing endpoints.** Fetch and read ALL frontend JS. Business logic, signing, hidden params, and API routes live there. Endpoints are only the starting point.
- **200 OK is NOT vulnerability confirmation.** Verify real business impact: did the DB value actually change, did you actually read another user's data, was a state check actually bypassed.
- **Model threats per feature, don't run a fixed checklist.** For every feature ask across 12 dimensions: data flow, privilege boundary, resource ownership, state change, client-controlled values, concurrency, output rendering, auth/session, server-side requests (SSRF), injection surface, file operations, business logic.

## Recon Phase (do this first)

1. `curl -sS --noproxy '*' -D - <target>` — capture headers: Server, X-Powered-By, Set-Cookie, framework fingerprints.
2. Fetch homepage + all linked JS files. Grep JS for: API paths, `/api/`, `/admin`, fetch/axios calls, hardcoded tokens, signing secrets, hidden parameters, role checks.
3. Directory/content discovery with ffuf/gobuster: `/admin`, `/api`, `/backup`, `/.git/config`, `/robots.txt`, `/swagger`, `/actuator`.
4. **Identify tech stack → load the matching CVE skill instantly.** Frameworks are "know it = solve it": ThinkPHP/Fastjson/Log4j/Shiro/Struts2/Spring → load `web-framework-cve`; 更多中间件(Grafana/Fastjson/Solr/Jumpserver/Dubbo/Airflow/ActiveMQ/ES/SpringBoot)→ load `middleware-cve-2`; Flask/Django/Jinja2/pickle → load `python-web-attack`; 模板注入({{7*7}}求值)→ load `ssti`; Java EL/SpEL/OGNL → load `expression-language-injection`; Log4Shell/JNDI → load `jndi-injection`; JWT gate → load `jwt-attack`; API/越权/IDOR/header伪造 → load `api-auth-advanced`; OA product → load `oa-system-attack`; AI platform → load `ai-platform-cve`. Do NOT re-derive a known framework vuln from scratch — the payload is in the skill.
5. Enumerate roles/accounts. If registration exists, create attacker + victim accounts.

## Vulnerability Decision Flow

Route by what the feature does:

- **Login / auth business** → SQLi in login, auth bypass (`admin'--`), weak JWT, default creds, response-based user enumeration. WAF in front → see waf-bypass-methodology.
- **Input reflected in response** → XSS (client) vs SSTI (server: test `{{7*7}}`→49 means server-side). SSTI often → RCE.
- **Any ID in request (user_id, order_id, doc_id)** → IDOR: swap to victim's ID, confirm you read/modify their data. Try encoded/hashed IDs, add ID where none asked, change method/filetype.
- **URL / host / callback parameter** → SSRF: point at `http://127.0.0.1`, `http://169.254.169.254/` (cloud metadata), internal services. Blind SSRF → use callback listener.
- **File upload** → bypass type check (see file-upload-methodology): double extension, content-type spoof, magic bytes, `.php`/`.jsp`/`.phtml`, polyglot, path traversal in filename.
- **Command / diagnostic / ping feature** → command injection: `; id`, `| id`, `$(id)`, backticks, newline injection.
- **Serialized blob (cookie/body/token)** → deserialization: see deserialization-methodology.
- **Report/export/template feature** → SSTI, XXE (if XML), formula injection.
- **Numeric/price/quantity in business flow** → logic flaw: negative values, integer overflow, race condition (concurrent requests), coupon/discount stacking.

## Confirmation Discipline

- Non-destructive PoC only: `whoami`, `id`, `cat /flag`, `touch /tmp/poc`. Never destroy real data.
- For each feature, before moving on, write a coverage note answering: what input surface, what behaviors, what depth did I test.
- For a "not vulnerable" conclusion, note what attack surface remains un-ruled-out.

## Flag Hunting (CTF context)

Flags commonly at: `/flag`, `/flag.txt`, `/challenge/flag.txt`, env vars, DB table `flag`, admin-only pages, or returned after privilege escalation. After any RCE, immediately `find / -name 'flag*' 2>/dev/null; cat /flag* 2>/dev/null; env | grep -i flag`.

## Output

Report per finding: target, vulnerable feature, vulnerability class, exact request/response evidence, business impact, and the flag if obtained.
