---
title: "Playbook - I Have Been Stuck for 30 Minutes"
category: misc
subcategory: meta
type: playbook
tags: [stuck, where-to-start, no-progress, unsticking, checklist, flag-format, assumptions, re-read-the-prompt, hints, time-management, give-up, rubber-duck, what-now, help]
summary: "A systematic unsticking checklist: re-read the prompt, verify the flag format, list your assumptions, find the intended-vs-actual gap, and decide when to move on."
when_to_use:
  - "You have made no measurable progress in 30 minutes"
  - "You have a working exploit locally that fails remotely"
  - "You have found 'the bug' but cannot turn it into the flag"
  - "You do not know what to try next"
related: [ctf-start, unknown-file, attack-surface-by-primitive]
---

## Rule zero

**Stop typing.** Being stuck is an information problem, not an effort problem. Doing the same thing faster does not help. Work through this list in order; do not skip ahead because a step "obviously does not apply".

Set a timer for 10 minutes and do the whole list before you resume what you were doing.

---

## 1. Re-read the challenge prompt, literally word by word

Read it out loud. For each noun and each verb, ask "why did they write that?"

- [ ] Does the **title** name a technique, a tool, an algorithm, or a pun on one? (`Twin Primes`, `Baby's First Heap`, `Ret2Basics`, `Not So Random`)
- [ ] Does the **description** contain a number? A version? A year? A name?
- [ ] Is there a word you skimmed over because you assumed you knew what it meant?
- [ ] Is there an explicit constraint ("the key is 8 characters", "only ASCII", "under 100 bytes")?
- [ ] Is there an implicit hint in the author's handle, the category, or the point value?
- [ ] Does the prompt say what you are supposed to *produce*, vs what you have been producing?
- [ ] Are there **attached files you have not opened**? Check every one.
- [ ] Is there a hint button, a pinned Discord message, or a `#challenge-name` channel?
- [ ] Was the challenge **updated** since you downloaded it? Re-download the handout.

```sh
# did the handout change?
sha256sum handout.zip; ls -la
```

---

## 2. Verify the flag format

More solved challenges are lost here than anywhere else.

- [ ] What is the exact flag format for this CTF? `ctf{...}`, `FLAG{...}`, `picoCTF{...}`, no braces at all?
- [ ] Is it case-sensitive? Did the scoreboard say "flags are case-insensitive"?
- [ ] Does the flag need wrapping? Many crypto/rev challenges give you the inner text only.
- [ ] Is the flag **inside** something you already have? Grep everything you have produced:

```sh
# grep every artefact you have generated so far, including binaries
grep -rniaE '[a-z0-9_]{2,15}\{[^}]{4,80}\}' . | head -40
# and the base64/hex-encoded forms
grep -raoE '[A-Za-z0-9+/]{20,}={0,2}' . | cut -d: -f2- | sort -u | while read -r b; do
  printf '%s' "$b" | base64 -d 2>/dev/null | grep -aiE 'flag|ctf\{'
done | head
grep -raoiE '(66|46)6c6167|[0-9a-f]{40,}' . | head
```
See `ctfbrain search flag-formats`.

- [ ] Did you submit it and get "incorrect"? Check for: a trailing newline, a trailing space, a smart quote, `l` vs `1`, `O` vs `0`, a non-ASCII character, URL encoding, an off-by-one truncation.

```sh
# show exactly what you are about to submit
printf '%s' "$FLAG" | xxd | tail -3
```

---

## 3. List your assumptions and break each one

Write them down. Literally, on paper or in your notes. An assumption you have not written down is one you cannot question.

Common false assumptions, by category:

| Category | Assumption that is usually wrong |
|---|---|
| all | "the handout matches what runs on the server" |
| all | "the obvious bug is the intended bug" |
| all | "this file is what `file` says it is" |
| crypto | "the modulus is a product of two primes" |
| crypto | "the random values are actually random" |
| crypto | "the plaintext is the flag" (it may be a key for the next step) |
| crypto | "the encoding is what it looks like" (base64 with a custom alphabet) |
| pwn | "the offset is the same remotely" |
| pwn | "the provided libc is the one in use" |
| pwn | "the buffer is the only thing I can overwrite" |
| web | "the endpoint list is complete" |
| web | "the WAF/filter is applied everywhere" |
| web | "the frontend and backend parse this the same way" |
| rev | "the decompiler output is correct" (check the disassembly) |
| rev | "the program does what its strings say" |
| forensics | "I extracted everything" |
| stego | "one layer of hiding" |
| misc | "the challenge is in the category it is filed under" |

For each one, design a 2-minute experiment that would disprove it.

---

## 4. Find the intended-vs-actual gap

Ask: **what did the author have to write on purpose for this challenge to exist?**

- A normal application would not have this function. Why is it here?
- A normal implementation would use the library. Why did they write their own?
- A normal challenge would not give me this extra file. What is it for?
- What in the handout have I **not used yet**? Every provided artefact is provided for a reason.

```sh
# inventory: which files have I actually opened?
ls -la; find . -type f -exec ls -la {} \; | sort -k5 -n
```

Checklist of "provided but unused":
- [ ] A libc / ld that you did not patch in
- [ ] An `output.txt` you only read the first line of
- [ ] A second ciphertext
- [ ] A public key you never parsed (`openssl rsa -pubin -text -in key.pub`)
- [ ] A `Dockerfile` you never read
- [ ] The source's *comments*
- [ ] The git history
- [ ] The second, third, fourth attachment

---

## 5. Re-do the triage you skipped

Go back to the entry playbook for the category and run **every** command, including the ones you assumed would be useless.

| Category | Playbook |
|---|---|
| Unknown file | `ctfbrain search unknown-file` |
| Crypto | `ctfbrain search crypto-triage` |
| RSA specifically | `ctfbrain search rsa-decision-tree` |
| Web | `ctfbrain search web-triage` |
| Pwn | `ctfbrain search pwn-triage` |
| Rev | `ctfbrain search rev-triage` |
| Forensics | `ctfbrain search forensics-triage` |
| Stego | `ctfbrain search stego-triage` |
| `nc host port` | `ctfbrain search remote-service` |
| Source handout | `ctfbrain search source-code-given` |
| "I have primitive X" | `ctfbrain search attack-surface-by-primitive` |

The universal five, again:
```sh
file *; strings -a * | grep -aiE 'flag|ctf\{'; binwalk -e *; exiftool -a -u -G1 *; xxd * | head -5
```

---

## 6. What to search, and how

Search in this order:

1. **CTF-Brain**: `ctfbrain search <the weird thing>`. Search the *symptom*, not your theory.
   ```sh
   ctfbrain search "format string"
   ctfbrain search unsorted-bin
   ctfbrain search "same n two e"
   ```
2. **The exact string**: paste a distinctive constant, an error message, or a function name into your search engine, in quotes.
3. **The algorithm name + "ctf"**: `"XTEA" ctf writeup`.
4. **The library + version + "CVE"**.
5. **Past CTFs**: if the challenge is by a known author or an obvious reuse, find last year's version of the same idea. CTFtime's writeup list for a similarly-named challenge is often a direct answer.
6. **The source of the code**: a distinctive comment or variable name often reveals the StackOverflow/GitHub snippet the author copied, and its known weakness.

Search terms that actually work: the magic constant (`0x9E3779B9`), the exact error string, the struct field names, the unusual function name, the flag-check shape.

---

## 7. Change the medium

Being stuck is often a representation problem.

- [ ] **Draw it.** The heap layout, the state machine, the data flow, the protocol exchange.
- [ ] **Write it down in one sentence**: "I can X, but I need Y, and the thing in between is Z."
- [ ] **Explain it to someone** (or to a text file). Half the time you find the answer mid-sentence.
- [ ] **Do it by hand once.** Manually perform the thing you are scripting; you will see what your script assumes.
- [ ] **Simplify.** Rebuild the challenge locally with tiny parameters (32-bit primes, a 4-byte flag, 2 heap chunks) and solve that first.
- [ ] **Invert the question.** Instead of "how do I exploit this", ask "if I were the author, how would I make this solvable?"

---

## 8. The "I have a bug but no flag" checklist

You found the vulnerability and cannot finish. The missing piece is almost always one of:

| You have | You are missing | Get it by |
|---|---|---|
| Arbitrary read | the address to read | a leak of the base (GOT, `environ`, a heap pointer) |
| Arbitrary write | a target that is actually called | `__free_hook`, a GOT entry, a return address, a vtable |
| RCE but no output | exfiltration | reverse shell, DNS/HTTP out-of-band, write to a readable file |
| SQLi but no output | a channel | UNION, error-based, blind boolean, time-based |
| XSS but no admin | a trigger | the report/bot feature; check it actually visits your URL |
| SSRF but no target | an internal service | read `docker-compose.yml`; scan `127.0.0.1` ports; try `169.254.169.254` |
| LFI but no useful file | a path | `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/fd/N`, log poisoning, `php://filter` |
| A decryption oracle | the right query shape | think about what one bit of output tells you, then binary-search |
| A shell as the wrong user | privesc | `sudo -l`, SUID binaries, capabilities, cron, writable paths, `ctfbrain search linux-useful-paths` |
| A file read as root | the right file | `/root/.ssh/id_rsa`, `/etc/shadow`, the app's config, the flag path from the Dockerfile |

---

## 9. Hygiene checks (yes, really)

- [ ] Is the VPN up? Can you reach the host at all? `nc -vz host port`
- [ ] Is the service actually running, or did someone crash it? Ask in the CTF chat.
- [ ] Are you attacking the right host/port? Copy-paste it fresh from the challenge page.
- [ ] Is your local environment the problem? Try in the CTF's provided Docker image.
- [ ] Did an earlier step silently fail? Re-run it and read the output this time.
- [ ] Is your script actually running the code you edited? (Stale `.pyc`, wrong directory, wrong venv.)
- [ ] Have you eaten / slept / stood up in the last 3 hours?

---

## 10. When to move on

Move on when **both** are true:
1. You have completed this checklist without a new idea.
2. Another unsolved challenge has more solves than this one.

Before you leave, spend 3 minutes writing a handoff note:

```markdown
### <challenge name> - PARKED at <time>
Given: <files>
Confirmed: <facts you have actually verified>
Ruled out: <what you tested and why it failed>
Current theory: <one sentence>
Next thing to try: <one concrete action>
Blocker: <the single missing piece>
```

Rotating off a challenge and coming back in two hours is the single highest-yield technique in CTF. The solve count on the scoreboard is also information: if 40 teams solved it and you cannot, you are missing something simple - go back to section 1. If 2 teams solved it, it is genuinely hard, and the cost of continuing is real.

- [ ] Post your blocker in the team channel with the handoff note. Someone else's fresh eyes cost them 30 seconds.
- [ ] Set a reminder to come back with 90 minutes left in the CTF.
- [ ] After the CTF, read the writeup **and then re-solve it yourself**. That is where the actual learning is.

`ctfbrain search ctf-start` for the team-level process.
