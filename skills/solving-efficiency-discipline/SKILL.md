name: solving-efficiency-discipline
description: Use at the START of every specialist task, before touching the target. Universal work discipline that prevents the biggest real-world efficiency killers observed in agent campaigns: pasting raw JSON/dumps into context, skipping methodology skills, unfocused multi-purpose commands, and burning turns on tool-chain mechanics. Load this first, then load the domain methodology (web-vuln/waf-bypass/reverse-solving/etc). Short, sharp, and applies to every challenge type.
---

# Solving Efficiency Discipline

Authorized CTF/assessment use. These rules exist because real campaigns showed agents wasting most of their context and turns on non-solving work. Follow them for EVERY task.

## Iron Rules

1. **Load the domain methodology FIRST, before any recon.** Your brief names it (web-vuln-methodology, waf-bypass-methodology, reverse-solving-methodology, pwn-methodology, etc). Call `load_skill` on it as your literal first tool call. Then `load_skill` attack-knowledge for the underlying mechanism + systematic method of this vuln class; `load_skill` verified-solve-playbook for pattern-level thinking. If you think a skill is "not in the list", re-check the list — it is there. Do NOT start probing the target without your methodology loaded.

2. **NEVER paste raw data into your context or reports.**
   - No full JSON dumps of API responses.
   - No full file contents / logs / scan output pasted back.
   - No "here is the complete original response" blocks.
   - Extract ONLY the fields that matter (a URL, a header, a version, a flag) into one line. Everything else stays in the sandbox filesystem — reference it by filename.
   - Your final report to cso is ≤200 chars: `code=|status=|flag=|vuln=|next=`.

3. **One command = one purpose.** Before each command, know exactly what single question it answers. Do not chain 5 unrelated probes into one command. If a command's output would be huge, pipe it (`head`, `grep`, `jq` filter) so only the useful part returns.

4. **Read output minimally.** Use `| head -c N`, `| grep KEYWORD`, `| jq '.field'` so tool results stay small. Prefer `execute_sync_command` (output comes back inline) — don't follow every command with a read.

5. **Think in hypotheses, not shotgun.** State: "vuln hypothesis: X → test: Y → expected: Z". If the test fails, revise the hypothesis. Do not re-run similar probes hoping one sticks.

6. **Know your toolchain, don't debug it.** If a tool (ghidra/ffuf/whatever) errors on invocation, switch to a known-working equivalent immediately (objdump/gobuster) rather than spending 3 turns fixing the wrapper. The binary is the target, not the tool.

7. **First-win-fast, then deepen.** Get the first flag/foothold with the cheapest valid path. Only then invest in the harder remaining flags. A partial solve that closes cleanly beats an elegant full solve that never lands.

## Per-challenge mini-loop (every specialist task)

1. `load_skill` domain methodology (first action).
2. One-line target summary: target addr, port, service, what we're hunting.
3. Recon with filtered output (2-4 commands max).
4. Hypothesis → test → result (repeat, ≤3 iterations).
5. On flag: self-verify locally if binary (see reverse-solving/pwn methodology), submit, report ≤200 chars.
6. On stuck after 3 distinct failed approaches: report `status=blocked|next_action=` and stop — do not grind.

## Output

Only the ≤200-char report line. Nothing else.
