---
title: "RANDOM CHEESE - TraceBash CTF 2026"
category: "web"
type: "writeup"
tags: ["web", "webexploitation", "logic", "api", "random", "cheese", "tracebash-ctf", "tracebash-ctf-2026", "2026", "ctf-writeup"]
summary: "Done by Rijwin Prince Rajesh from Team ZERODAY GUYS"
source:
  name: "CTFtime writeup #40901"
  url: "https://ctftime.org/writeup/40901"
original_source: "https://github.com/rijwinprince-0x/CTF-Writeups"
ctf:
  name: "TraceBash CTF 2026"
  year: 2026
  challenge: "RANDOM CHEESE"
---

## Metadata

- **CTF:** TraceBash CTF 2026
- **Task:** RANDOM CHEESE
- **Author team:** ZERODAY GUYS
- **CTFtime tags:** webexploitation, logic, api
- **CTFtime:** <https://ctftime.org/writeup/40901>
- **Original writeup:** <https://github.com/rijwinprince-0x/CTF-Writeups>

---
**Done by Rijwin Prince Rajesh from Team ZERODAY GUYS**

> *Note: The original PDF write-up linked above includes full screenshots and visual evidence from the challenge interface, exploit script, and terminal execution.  
> GITHUB:<https://github.com/rijwinprince-0x/CTF-Writeups*>

\---

### Challenge   
* **Name:** Random Cheese  
* **Category:** Web  
* **Points:** 100  
* **Description:** Jerry's finally opened his dream cheese shop, and Tom is furious! Every customer gets a lucky draw — spin the wheel 10 times and score 85+ to win the grand meal. But Tom rigged the system to make sure nobody ever gets THAT lucky... or did he?

### Initial Analysis

**Scouting**  
* Reviewing the challenge details, the objective is to score 85 or more points within 10 spins on a lucky draw wheel.  
* The web interface displays a target score of 85+, a spin counter, and a "Claim Flag" button.  
* The description explicitly hints that the system is rigged, suggesting standard spins through the UI will not yield the required score.

**Identifying the Vulnerability**  
* Based on the exploit script, there is an unprotected or hidden endpoint located at `/update_lucky`.  
* This endpoint accepts a POST request with a `lucky_number` parameter, allowing the attacker to arbitrarily manipulate the game's state or RNG mechanism to guarantee a winning score.

**Exploitation**  
* The Python script automates the exploit by first registering and logging in a random user.  
* It sends a POST request to `/update_lucky` with the data payload `{"lucky_number": 854}`.  
* It then loops to send 10 consecutive POST requests to the `/spin` endpoint to complete the game requirements.  
* Finally, a POST request is sent to the `/claim` endpoint, and the script uses regex to extract the flag from the server's response.  
* The terminal output confirms the successful execution and reveals the extracted flag.

### Flag  
* `TBCTF{t0m_4nd_j3rry_l0v3s_ch33s3_4nd_r4nd0mness}`

### Solution Summary  
* Register and log in a new user session on the platform.  
* Inject a high value by sending a POST request to `/update_lucky` with a `lucky_number` payload.  
* Execute 10 spins by sending automated POST requests to the `/spin` endpoint.  
* Retrieve the flag by sending a final POST request to `/claim`.

**GitHub Link:**  
```text  
<https://github.com/rijwinprince-0x/CTF-Writeups>

> The original PDF write-up hosted on GitHub includes full screenshots and visual evidence from the challenge interface, exploit script, and terminal execution.
