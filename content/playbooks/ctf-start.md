---
title: "Playbook - The Competition Just Started"
category: misc
subcategory: meta
type: playbook
tags: [ctf-start, where-to-start, competition, team-setup, tooling-checklist, triage-order, note-taking, challenge-selection, scoreboard, jeopardy, workflow, first-30-minutes, environment]
summary: "First 30 minutes of a CTF: environment check, team split, the triage sweep across all challenges, note-taking, and how to pick what to work on."
when_to_use:
  - "A CTF just started and you want a repeatable opening"
  - "You are organising a small team and need a division of labour"
  - "You want a pre-event tooling checklist"
related: [stuck, unknown-file, flag-formats, wordlists-and-resources]
---

## T-minus: before the CTF starts

### Environment (do this the day before, not at minute zero)

```sh
# 1. A working analysis VM/container. Verify, do not assume.
docker pull kalilinux/kali-rolling
# or keep a dedicated image with your tools baked in

# 2. Smoke-test the tools you will definitely need.
python3 -c "import pwn, Crypto, sympy, requests; print('py ok')"
which gdb radare2 ghidra binwalk exiftool tshark ffuf sqlmap john hashcat nmap 7z sage
gdb -q -ex 'pi print(pwndbg.__name__ if "pwndbg" in dir() else "")' -ex quit 2>/dev/null

# 3. Wordlists present and decompressed.
ls -la /usr/share/wordlists/rockyou.txt /usr/share/seclists 2>/dev/null
# `ctfbrain search wordlists-and-resources`

# 4. A scratch directory template.
mkdir -p ~/ctf/<eventname>/{crypto,web,pwn,rev,forensics,stego,misc,osint,notes}
```

### Pre-flight checklist

- [ ] Registered, team created, everyone on the team page
- [ ] VPN config downloaded and tested (`ping` the gateway)
- [ ] Team chat channel created, one channel **per challenge** if the platform allows
- [ ] A shared notes doc (see section 4) created and linked in the channel
- [ ] Flag format known and pinned
- [ ] Rules read: is brute-forcing the scoreboard allowed? flag sharing? dynamic scoring?
- [ ] Your local toolchain smoke-tested (above)
- [ ] Sleep schedule planned if it is a 48h event

---

## Minute 0-10: orient

```sh
# 1. Read the rules page. Actually read it.
# 2. Find and pin the flag format.
# 3. Open every challenge and download every attachment, all at once.
# 4. Start a notes file.
```

Bulk-download the handouts and get an inventory immediately:

```sh
cd ~/ctf/<event>
# after downloading everything into ./handouts
for f in handouts/*; do printf '%-40s %s\n' "$(basename "$f")" "$(file -b "$f")"; done
# unzip everything into per-challenge dirs
for z in handouts/*.zip; do d="${z%.zip}"; mkdir -p "$d" && unzip -q -o "$z" -d "$d"; done
```

**Do not start solving yet.** The first ten minutes are for building the map.

---

## Minute 10-30: the triage sweep

Go through **every** challenge and spend at most 90 seconds each. Produce one line per challenge:

```
<name> | <category> | <points> | <solves> | <artifact type> | <first impression> | <owner>
```

For each, run the 60-second identification from the matching playbook:

| Handout | Sweep command | Playbook |
|---|---|---|
| Any file | `file *; strings -a * \| grep -i flag; binwalk *` | `ctfbrain search unknown-file` |
| A URL | `curl -sSik URL \| head -40` | `ctfbrain search web-triage` |
| `nc host port` | `nc -v host port` (look at the banner) | `ctfbrain search remote-service` |
| An ELF | `checksec --file=./f; nm -D ./f` | `ctfbrain search pwn-triage` / `rev-triage` |
| `.py`/`.sage` + `output.txt` | read the script | `ctfbrain search crypto-triage` |
| `.pcap` | `tshark -r f -q -z io,phs` | `ctfbrain search forensics-triage` |
| An image/audio | `exiftool f; zsteg -a f` | `ctfbrain search stego-triage` |
| A `.sol` | read it | `ctfbrain search web3-audit` |
| An `.apk` | `jadx -d out f` | `ctfbrain search jadx` |

Output of this phase: a sorted list of challenges by **(estimated effort) / (points)**, and an owner per challenge.

---

## Team setup

### Roles (for a team of 3-6)

| Role | Owns | Why |
|---|---|---|
| **Triager / captain** | the sweep, the board, reassignments | someone must hold the whole map; rotates people off stuck challenges |
| **Crypto** | crypto, some misc | crypto is the most specialised; one person deep beats two shallow |
| **Web** | web, cloud, some misc | needs Burp set up and a stable proxy |
| **Pwn** | pwn, some rev | needs the right libc/Docker environment |
| **Rev** | rev, mobile, some misc | slowest category; start early |
| **Forensics/Stego/OSINT** | forensics, stego, osint | mostly tooling breadth, good for a generalist |

For a team of 2: one takes crypto+rev+pwn, the other web+forensics+stego+misc, and both triage.
For a solo player: do the sweep, then work strictly in ascending order of estimated effort.

### Rules of engagement

- **One owner per challenge.** Two people silently working the same thing is the most common team failure.
- **Announce when you start and when you park.** Post the handoff note (see `ctfbrain search stuck`).
- **Ask for a second pair of eyes at 45 minutes, not at 3 hours.**
- **Never submit a flag someone else found without telling them.** Post it in the channel first.
- **Post every leak, every partial, every weird observation** in the challenge channel, even if it seems useless. It is usually the key for whoever picks it up next.
- **Keep one person unassigned** during the last 4 hours to float onto near-solves.

---

## Note-taking

One file per challenge, created the moment you open it. This is non-negotiable in a 48h event.

```markdown
# <challenge name>  [<category> / <points>]
URL/host: 
Files: 
Flag format: 

## Given
- 

## Observations
- [HH:MM] 

## Tried (and result)
- [ ] 

## Current theory


## Next action


## Artifacts
- solve.py
- notes/leak.txt
```

Rules:
- Timestamp every observation. You will need the ordering later.
- Record failures with the *reason* they failed, not just "did not work".
- Paste the exact commands you ran. Future-you will re-run them.
- Keep every intermediate file. Name them `01_extracted.bin`, `02_decoded.txt`.
- Keep `solve.py` in the challenge directory and commit it as you go:
  ```sh
  cd ~/ctf/<event>/<chal> && git init -q && git add -A && git commit -qm wip
  ```

Shared board (a pinned message or a spreadsheet) with columns: challenge, category, points, solves, owner, status (`untouched`/`in progress`/`stuck`/`solved`), blocker.

---

## How to pick a challenge

Pick in this order:

1. **Anything you can solve in under 15 minutes.** Free points build momentum and rank.
2. **The highest-solves unsolved challenge in your category.** Solve count is the crowd's difficulty estimate and it is accurate.
3. **Challenges in a category you are strongest in**, if they are near the top of the solve list.
4. **A challenge that is a known technique you have in your notes.** Revisiting is cheap.
5. **Long-running compute jobs first** (factorisation, hash cracking, `angr`, `ffuf`) - start them, then work on something else while they run.

Do NOT pick:
- The 500-point challenge with 0 solves in hour one.
- A challenge in your weakest category when there are unsolved ones in your strongest.
- Something someone else is already on.

Watch the scoreboard: when a challenge's solve count jumps from 2 to 20, it just got easier (a hint dropped, or the intended path became obvious). Re-check parked challenges when their solve count moves.

Dynamic scoring: points decay with solves. Solving early is worth more, but an unsolved challenge is worth zero. Do not hoard.

---

## Standing background jobs

Start these early; they cost you nothing while you work on something else.

```sh
# factorisation of any RSA modulus you have
echo "<n>" | timeout 3600 yafu "factor(@)" &
# hash cracking
hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule &
# directory brute force on every web challenge
ffuf -u https://chal/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc all -fc 404 -o ffuf.json &
# steghide password brute
stegseek chal.jpg /usr/share/wordlists/rockyou.txt &
# angr on a rev challenge
nohup python3 angr_solve.py > angr.log 2>&1 &
```
Keep a `jobs.md` listing what is running, where its output goes, and when you started it.

---

## Minute-by-minute template for the first hour

| Time | Action |
|---|---|
| 0-3 | Rules, flag format, VPN up, notes dir created |
| 3-10 | Download every handout; inventory with `file` |
| 10-25 | 90-second triage of every challenge; fill the board |
| 25-30 | Assign owners; start background jobs |
| 30-45 | Everyone solves the easiest thing in their lane (first blood on the freebies) |
| 45-60 | Captain re-sorts the board by solve count; reassign |

---

## Endgame (last 4 hours)

- Captain re-reads every parked challenge's handoff note and reassigns with fresh eyes.
- Everyone posts their **single blocker** in one message; the team attacks blockers, not challenges.
- Stop starting new challenges 2 hours before the end; finish what is 80% done.
- Submit everything you have, including partial/guessed flags if submissions are unlimited.
- In the last 30 minutes, check the scoreboard for challenges that you triaged as hard but that now have many solves.

---

## After the CTF

- [ ] Write up every challenge you solved, while you remember it.
- [ ] For every challenge you did **not** solve, read the writeup and then re-solve it from scratch.
- [ ] Add every new technique to CTF-Brain as a `technique` file with working code.
- [ ] Add every tool you had to install mid-CTF to your base image.
- [ ] Note every time you lost more than 20 minutes to environment/tooling; fix it before the next event.

`ctfbrain search stuck` when the opening is over and you are mid-challenge.
