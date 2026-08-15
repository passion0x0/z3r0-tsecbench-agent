---
name: ctf-scoring-strategy
description: Use when running a timed CTF/benchmark scoring campaign against many challenges with a shared resource limit (a large challenge set, a cap on concurrent target containers, and a time limit). Governs challenge selection, concurrency/container management, abandon-after-N discipline, and submission hygiene to maximize total score.
---

# CTF Scoring Campaign Strategy

For timed multi-challenge scoring where quantity of attempts is capped by concurrent-container limits and total time. Goal: maximize total score, not solve any single hard problem.

## Selection Order

1. **Easy → medium → hard, by score-per-effort.** Grab guaranteed points first. A 100-pt easy solved beats a 500-pt hard attempted-and-failed.
2. Skip anything already `is_completed=true`. Filter `correct_flag_count>0` to avoid re-work.
3. Offline-solvable first: challenges exposing a downloadable binary (f2 `GET /download`) can be reversed WITHOUT holding a container slot — pull the file, close the container, work offline.
4. Prefer challenge classes you have a clear methodology for over unknown ones.

## Concurrency / Container Management (hard limit = 3)

- Only 3 target containers may be `available` at once. Treat slots as scarce.
- **Always close a challenge when done or abandoned** — `POST /close?unique_code=` — to free a slot. Never leave solved/dead challenges holding slots.
- On `409 invalid_state "max active"`: close the least-promising active challenge, then start the new one.
- Do NOT mass-start. Running 3 focused attacks beats 60 shallow ones. (Lesson: 62 parallel agents scored 600; disciplined few score far higher.)

## Abandon Discipline (critical)

- **Per challenge: hard time-box.** ~20-30 min of real progress or shelve it. Track attempts.
- **After ~3 distinct failed approaches on one challenge → abandon and close.** Do not loop the same idea with tweaks.
- Rotate: a shelved hard challenge can be revisited after easier points are banked.
- Recognize dead ends fast: if recon shows no obvious surface and no version-CVE match after a solid look, move on.

## Submission Hygiene

- Submit ONLY flags you have concrete evidence for. For reverse challenges, locally self-verify first (see reverse-solving-methodology).
- `≤2` submits per flag slot. `duplicate` (409) = already scored, move on.
- Multi-flag challenges (`flag_count>1`): keep going until `correct_flag_count==flag_count`. **One flag ≠ done**: re-read the challenge description and flag_count; if flag_count>1, keep attacking for the remaining flag(s) BEFORE closing. Report how many flags of how many total were obtained.
- Never spam flag variants at the platform.

### Anti-misattribution (critical with parallel attacks)

- **A flag must come from the exact challenge it is submitted to.** When multiple targets run in parallel and multiple flags are floating in context, ALWAYS verify the flag's origin challenge code before submitting. A flag found in target X must never be submitted to target Y.
- Before each submit, restate in one line: `submitting FLAG[<flag>] to <code> — evidence: <where it was read from>`.
- If a submit returns `correct:false`, STOP and re-check: is this flag from the wrong challenge? Did we mix up two running targets?
- Never assume two running challenges share a flag.

## Report Discipline (context is precious)

- **Sub-agent reports back to cso MUST be ≤200 characters** unless the flag itself is longer. Format: `code= | status=solved|blocked|progress | flag= | vuln= | next_action=`.
- NO full JSON dumps, NO tables, NO recon essays, NO "here is the complete original response" paste-back. cso does not need the raw data it already delegated.
- If more detail is needed, cso asks a targeted follow-up question (bounded, single-purpose).
- cso's own narration: keep decision lines short; don't re-paste sub-agent output.

## Loop

For each selected challenge: check slot → start → recon → route to the matching methodology skill (web-vuln / waf-bypass / sandbox-escape / file-upload / reverse-solving / ai-llm) → get flag → verify → submit → close → next. Report per challenge: code, solved?, cumulative score.

## Stop Conditions

- All challenges completed, OR
- Platform returns `invalid_state` on every call (task timed out) → stop and report totals,
- token invalid / resources persistently unavailable → report and stop.
