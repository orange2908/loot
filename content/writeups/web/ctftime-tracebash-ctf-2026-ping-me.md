---
title: "PING ME - TraceBash CTF 2026"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "rce", "command-injection", "webexploitation", "ping", "tracebash-ctf", "tracebash-ctf-2026", "2026", "ctf-writeup"]
summary: "Done by Rijwin Prince Rajesh from Team ZERODAY GUYS"
source:
  name: "CTFtime writeup #40900"
  url: "https://ctftime.org/writeup/40900"
original_source: "https://github.com/rijwinprince-0x/CTF-Writeups"
ctf:
  name: "TraceBash CTF 2026"
  year: 2026
  challenge: "PING ME"
---

## Metadata

- **CTF:** TraceBash CTF 2026
- **Task:** PING ME
- **Author team:** ZERODAY GUYS
- **CTFtime tags:** rce, command_injection, webexploitation
- **CTFtime:** <https://ctftime.org/writeup/40900>
- **Original writeup:** <https://github.com/rijwinprince-0x/CTF-Writeups>

---
**Done by Rijwin Prince Rajesh from Team ZERODAY GUYS**

> *Note: The original PDF write-up linked above includes full screenshots and visual evidence from the challenge interface, exploit script, and terminal execution which is in GITHUB.*

\---

### Challenge  
* **Name:** Ping Me  
* **Category:** Web  
* **Points:** 100  
* **Description:** Tom wants to ping Jerry's IP, but the paranoid network admin built an "unbreakable" firewall around the ping utility. Digits and dots only — absolutely no funny business. Can you help Tom reach Jerry through the fortress of rules?

### Initial Analysis

**Scouting**  
* Reviewing the challenge description, the goal is to interact with a web-based ping utility, presumably to achieve remote code execution (RCE) or read a flag file.  
* The web interface provides an input field for a "TARGET ADDRESS" and explicitly states constraints: "Max 15 characters" and "NO LETTERS ALLOWED".  
* The description reinforces these constraints, mentioning "Digits and dots only". This indicates a strict input validation or sanitization mechanism is in place on the front end or back end.

**Identifying the Vulnerability**  
* Despite the stated restrictions, the provided terminal exploit demonstrates a command injection vulnerability.  
* The exploit bypasses the "no letters" restriction by using shell wildcard characters (`?`) instead of letters to represent the path to a binary.  
* The exploit uses a newline character (`\n`) to terminate the intended `ping` command and start a new command, a classic technique for command injection in Unix-like environments.

**Exploitation**  
* The terminal command `curl -s -X POST https://web-ping-me.tracebash.xyz/api/ping --data-binary $'1\n/???/????????' -H "Content-Type: text/plain"` executes the attack.  
* It sends a POST request to the `/api/ping` endpoint.  
* The payload is `1\n/???/????????`.  
* `1` is a valid IP component to satisfy the initial ping command.  
* `\n` injects a new line, separating commands.  
* `/???/????????` uses wildcards to execute a command without using letters. Given common Unix paths, this likely resolves to `/bin/catflag` or a similar custom binary placed by the challenge creator, or potentially a standard utility like `/bin/getflag` if it matches the pattern.  
* The server response confirms the execution of the first command (pinging 1) and then returns the output of the injected command, which is the flag.

### Flag  
* `TBCTF{0ld_5ch00l_c0mm4nd_1nj3c710n_0n_573r01d5}`

### Solution Summary  
* Identify the backend API endpoint for the ping utility (`/api/ping`).  
* Craft a payload to bypass alphanumeric filters using shell wildcards (e.g., `?`).  
* Inject the payload using a command separator (like a newline character `\n`) via a direct API request (using `curl`).  
* Analyze the JSON response to extract the executed command's output containing the flag.

**GitHub Link:**  
```text  
<https://github.com/rijwinprince-0x/CTF-Writeups/blob/main/TraceBash%20CTF%20writeup.pdf>

```  
**Note to include in your write-up description:**  
> The original PDF write-up hosted on GitHub includes full screenshots and visual evidence from the challenge interface, exploit script, and terminal execution.  
>
