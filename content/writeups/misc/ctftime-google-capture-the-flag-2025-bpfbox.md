---
title: "BPFBOX - Google Capture The Flag 2025"
category: "misc"
subcategory: "pow"
type: "writeup"
tags: ["misc", "proof-of-work", "bpfbox", "pow", "google-capture-the-flag", "google-capture-the-flag-2025", "2025", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #40324"
  url: "https://ctftime.org/writeup/40324"
original_source: "https://ctf.krauq.com/googlectf-2025#bpfbox-53-solves"
ctf:
  name: "Google Capture The Flag 2025"
  year: 2025
  challenge: "BPFBOX"
---

## Metadata

- **CTF:** Google Capture The Flag 2025
- **Task:** BPFBOX
- **Author team:** Friendly Maltese Citizens
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40324>
- **Original writeup:** <https://ctf.krauq.com/googlectf-2025#bpfbox-53-solves>

---
For the complete documentation index, see [llms.txt](https://ctf.krauq.com/llms.txt). This page is also available as [Markdown](https://ctf.krauq.com/googlectf-2025.md).

## Misc

### メガA (110 solves)

#### Description:

Join the 16-bit revolution! Can you help Sonk the Rabbit find all flags? Submit your recording to get the flag: python3 submit.py solution.inp [mega.2025.ctfcompetition.com](https://www.google.com/url?sa=D&q=http%3A%2F%2Fmega.2025.ctfcompetition.com) 1337 

Note: Submit the flag starting with "CTF{A:" here. For submitting the other flag, see the challenge titled "メガB". 

Note 2: To make the メガ challenges less annoying for those who already solved it locally, the ability to get the flag from the server may depend on mame version you installed. This wasn't obvious and we apologise. The version we run at the server is 0.277+dfsg.1-0ubuntu1~ppa3~noble1 and it comes from ppa:c.falco/mame.

**Resources:**

Static resources:[chall](https://storage.googleapis.com/2025-attachments/b9c654bb16bd4d60b557ddffdff1ebec2f95a22d8089dff576d93fb70553268962e6f5569e9af8706314ce33c6030695dd478584c29f1c38ab93eb53ea2cc583.zip)

#### Solution:

Unzipping the challenge, we see a misc-mega-rust-1 folder with a bunch of rust game files and a Sega Mega Drive ROM image (sonk.md). Below is the README.md for convenience.

Copy

```
    # Mega Sonk in MegaRust
    
    To run the game:
    
    ```
    mame genesis -cart sonk.md
    ```
    
    Record your solution and send it up to the server to get the flag! Make sure your recording is at most 5 minutes long.
    
    ```
    mame genesis -cart sonk.md -record solution.inp
    python3 submit.py /home/user/.mame/inp/solution.inp mega.2025.ctfcompetition.com 1337
    ```
    
    To rebuild the game:
    
    ```
    make sonk.md
    ```
    
    On the first run this builds the compilation toolchain which could take up to half an hour.
    
    Rebuild and run the game:
    
    ```
     make run
    ```
    
    
    ## Credits
    
    Compilation toolchain based on
    * https://github.com/ricky26/rust-mega-drive
    * https://github.com/rust-lang/rustc_codegen_gcc
    
    Graphics credits:
    * https://opengameart.org/content/dashie-supertux-advance-style
    * https://opengameart.org/content/plastic-shamtastic
    * https://opengameart.org/content/wasp-0
```

Running the game following the instructions, we can quickly explore the entire map and see the two flags.

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FxwjcGxszqiv02SIKO2GQ%252Fimage.png%3Falt%3Dmedia%26token%3Db0453485-8185-48c2-9349-80069cd8b6eb&width=768&dpr=3&quality=100&sign=c65242d87f0bfe649c8fa18cd5a16a16&sv=3)

Flag A

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252F1vrHbNoRwqVjlVpwDHmg%252Fimage.png%3Falt%3Dmedia%26token%3D18a672bf-3eaa-4926-8a69-17dcb379ab0e&width=768&dpr=3&quality=100&sign=12c4b3439f21716fb7eef1d94c1c7a1f&sv=3)

Flag B

We can't walk into the spikes for flag A and we can't jump high enough to hit flag b. The only enemies are wasps which knock us back if we hit them but we don't take damage (similar to hitting spikes). We can build up a lot of speed and jump pretty far when jumping off a hill. Finally, we can go off screen slightly on the left and right.

Early theories were that we could do something off screen or building up speed and hitting hills/enemies/spikes could cause glitches. We also thought maybe the flag collision area might shift over time. We are given all the tools needed to rebuild the game so we can modify it to give us some debugging information.

Here are all the mods I added in the game.rs draw function (right after the first if statement):

This allows us to see everything that could be significant for the challenge. We can see absolute X position (a vertical line every 500 pixels), x/y position of collision boxes for the flags and the player (rendered with a vertical and horizontal line), an x/y position indicator (with flags to represent digits because numbers can't be rendered on the map and there's no terminal), a speed indicator, and a few other things. The below two images show some examples.

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FMkXRIrFsayQfqgjTP5rx%252Fimage.png%3Falt%3Dmedia%26token%3D3b7cd474-3858-42dd-ab98-20f856fa8b3e&width=768&dpr=3&quality=100&sign=03826476af8d404ae0959a1afb62a0a5&sv=3)

X/Y relative position indicators (left), horizontal position of player (green) horizontal position of flag (white), vertical marker for 500 feet (white)

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FKp5NhRf5xlrbgSF8OPZe%252Fimage.png%3Falt%3Dmedia%26token%3D04ae79f2-2718-42ed-a3f2-0693ebad6510&width=768&dpr=3&quality=100&sign=ddfc03d572c3cc7bae8fdb1ab7077c81&sv=3)

Checking flag position (left vertical line) when we're hit off screen

These mods let us learn a few interesting things like when we're off screen, we quickly hit an invisible wall, but we still build up "speed" when we move against it. Also when we're hit by a wasp off screen downhill, our y position stays at the last position on screen until we move. We also can see if the flag collision our or collision box ever gets moved somehow.

This represents all the information that we can learn by rebuilding the game. Does any of this help? Sadly no.

Flag A is very simple, we just need to be hit offscreen into the spikes. There's a wasp suspiciously close to the right of the spikes with the flag, if we move ourself to the left of the screen and let ourselves get hit, we can go through the spikes that haven't spawned and get it. 🤷‍♂️

### メガB (87 solves)

Flag B ended up being nothing related to being off screen, velocity, collision boxes, etc., but rather the spawn mechanism of the wasp. 

When we first see the wasp spawn coordinate on screen, it will spawn at that time, but it doesn't despawn any wasps that were already existing, meaning we can walk back and forth with the right side of the window right at the spawn point to spawn multiple wasps at the same time. This is the only obvious mechanism that can be abused, and after a period of time trying to spawn as many as possible, we'll see that if the right side of the screen is exactly on the spawn point, it'll constantly spawn wasps until the game breaks.

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252F14AblpVU0J2xFcQSo4NZ%252Fimage.png%3Falt%3Dmedia%26token%3D51d3a681-7677-40c1-bd21-6d290fc76650&width=768&dpr=3&quality=100&sign=2cccb9a3eb5d9a502a1ce138f70c285a&sv=3)

Player is now above Flag B, can see their feet when moving side to side

The player will conveniently glitch up to the top of the screen when there are too many wasps. Then, just walking back and forth will eventually collect the flag. Following the instructions, we can generate recordings (needs to be the unmodded game) to submit both flags. A lot of "unnecessary" game mods were done but this helps through process of elimination to narrow down where to look for the solution.

### 🩸BPFBOX (53 solves)

#### Description:

I heard people can write LSMs using BPF, so I built one.

bpfbox.2025.ctfcompetition.com 1337

**Resources:**

Static resources:[chall](https://storage.googleapis.com/2025-attachments/bf17a3af285b9346a35fddd9b3208f2eb20fefa5bcacb9a6dc896de4ed26b032b35dd286540c22272eda14cc8863cc727c2ad422dbd8bf61520a94e403e1a2ee.zip)

#### Solution:

Unzipping the challenge, we see the following docker image.

Basically, connecting to this challenge drops us into a shell where a BPF probe seems to kill any process that tries to read /flag.txt. The proof of work script is tuned to take a long time (at least 30 seconds to a minute on my machine) and it kicks you out after a minute, so building the challenge with the Dockerfile is probably required to reliably solve it. However I got lucky and solved it in a few minutes so I didn't have to. 😅

Testing random commands to see what happens, our command gets echo'd back to us if we try to directly access flag.txt. Thinking maybe the BPF probe only checks if the process is trying to access flag.txt as soon as it's created, I added a sleep before it and it worked.

### Fishmaze (30 solves)

#### Description:

Escape the maze.

#### Solution:

There's no sources given, we just have the html on the launched instance.

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FVndRHvGbDZzd3sTmExSC%252Fimage.png%3Falt%3Dmedia%26token%3D1597cbb8-bf01-4b31-a866-37108a47a199&width=768&dpr=3&quality=100&sign=dafba113f1a4a51b1400500900f2f383&sv=3)

Launched instance, we can write player kernel and if it passes a syntax check, see the run

The html code doesn't help us too much aside from the hint at the end. It basically renders our fish moving based on the player_kernel, which runs every tick. Whatever we do seems to just be repeated each time, so if we have it move one direction, we keep moving in that direction. We need to either be able to choose decision based on nearby objects (very hard/impossible to leave the maze on a generic ruleset) or figure out how to use the AUX_DATA as memory to store a sequence of memories.

The problem is random compilations either succeed or don't succeed and there's no debugging info provided on why compilations don't succeed. To solve this, we can use asserts to learn more about the system. The following script is used to determine what mapdata_ref actually is.

This does a binary search for each character of the type, so sees if it's upper/lower/digit/symbol, then narrows down on what it is with asserts one at a time. A failed compile means it's not that. Running this we find it is `Traced<int32[]>with<DynamicJaxprTrace>` and looking into that, it is JAX. Knowing this, we can build this simple proof of concept to change directions based on tick.

From here, it's simple iteration to build up the full solution. Count out the amount to move, run it, make adjustments, wait to avoid the enemies, and we win.

### HWSIMv2 (27 solves)

#### Description:

Last year we were notified that our circuitry was backdoored, so now we formally verify our designs before they get sent to the factory. Implement an instruction decoder for our next-gen CPU!

hwsim.2025.ctfcompetition.com 1337

**Resources:**

Static resources:[chall](https://storage.googleapis.com/2025-attachments/67457531324d182a5644f7ccb1b5aaa59a210c4d8a164053c76c9745b10c49e382806f0cb8d852d24ff184d69d7513b4f88105935a02cf069be5f5c6e9b78ec0.zip)

#### Solution:

Unzipping the challenge, we see the following challenge.

Basically we need to build the CPU and then run instructions to print the flag. A teammate (quasar) wrote the CPU so I don't fully understand that part, but after using AI to build a solve script, we have the final solution here.

Basically we automate solving the pow and then paste in the instructions, after 5 it will either verify or not. Then we send a payload to dump it. The following is the explanation of all this written by AI.

#### 1\. What the verifier is supposed to check

For every possible assignment of the **32 “basic-input” bits**

the solver proves that all required outputs satisfy the official formulas, the most important of which is the **security check** :

If _any_ model violates _any_ equality, Z3 finds a counter-example and the menu prints “Formal verification failed!”.

* * *

#### 2\. Two constants are enough to break the proof

We add **five** tiny gates (the first five lines of the new `working2.txt`):

  * `security_exception` is a **hard-wired 0**.

  * `is_root_now` is a **hard-wired 1**.


Now, for every possible input valuation,

so the equality holds identically. The solver happily reports

All the _other_ outputs (`is_load`, `is_store`, …) are implemented exactly as the organisers’ reference circuit, so their equalities hold too.

> **Key bug:** The challenge treats a wire name that appears in _basic_inputs_ and in the gate list as **one single Boolean variable**. By giving it a gate definition we _override_ the would-be input instead of adding a constraint between two distinct signals.

* * *

#### 3\. Why it works at run-time even in user mode

During emulation the dispatcher calls

`known` initially contains only the _real_ run-time value of `is_root_now` ( `True` in kernel mode, `False` otherwise ). But because `security_exception` is **not** in that dict, the recursive NAND evaluation walks the circuit and discovers that it is the constant 0, **never** **consulting**`**is_root_now**`**at all**.

So:

  * user code can execute `load` / `store` to any address, or call `putc`, without ever tripping the check;

  * we do **not** need to stay in kernel mode or ret-leaf from a `syscall`.


* * *

#### 4\. The 105-byte flag-dump program

Each repetition does

for `xx = 0x80 … 0x99`, followed by `0f` (HALT). Because `security_exception` can never go high, every `LOAD` from the kernel half of RAM succeeds even though we remain in user mode, and every byte is printed via `PUTC`.

* * *

#### 5\. Why the constant trick is undetectable by the verifier

  * **Quantifiers** – the solver checks the equalities for _all_ possible assignments, but our gates _force_ one particular assignment (`is_root_now = 1`, `security_exception = 0`), making every clause true.

  * **No extra constraint** – the organiser intended “` _is_root_now_` _is an independent input you may_ _**read**_ _, not_ _**drive**_ ”. By re-defining it as a gate output we silently removed that degree of freedom, but the verifier never notices: it still has a single Boolean `is_root_now`, only now equated to a NAND of two zeros.


* * *

#### 6\. Bottom line

The whole exploit is a textbook _“drive an input”_ hardware-Trojan:

  1. Synthesize constants with three NANDs.

  2. Wire `security_exception` to **0**.

  3. Wire `is_root_now` to **1** so the spec equation stays tautologically true.

  4. Keep every other output behaviourally identical, so the verifier has nothing else to complain about.

  5. Run any user program you like – the flag sits unprotected at `0x80+`.


That’s why the menu shows “Looks good!” yet the remote chip obediently leaks `CTF{…}` a few milliseconds later.

## Crypto

### numerology (218 solves)

#### Description:

I made a new cipher, can you help me test it? I'll give you the key, please use it to decrypt my ciphertext.

**Resources:**

Static resources:[chall](https://storage.googleapis.com/2025-attachments/5b0d78bf17f82eca5d41baa852ea1abdf8d81a63c16f5c42c3de6b164b5428b6aeefc0bc83ac1ac3d4967946362c40bfdb346e61b45c09a3f259031feb0e6365.zip)

#### Solution:

I wanted to see if my new automated AI solver could solve a GoogleCTF question, but unfortunately only using o3 on the backend will do it one-shot. Basically the solution can be found by decompiling the pyc (either pylingual.io or use pycdc on your computer, one of the few options available for python 3.12), and then passing it in to o3.

Using GPT 4.1 mini on the backend though, my automated solver was able to solve with a few (a lot) of nudges. Take a look at https://krauq.com and join the discord.

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FsAZxMrugO5zmUBU2hu5i%252Fimage.png%3Falt%3Dmedia%26token%3Db301de8b-84b2-4f85-8438-219378ff69bb&width=768&dpr=3&quality=100&sign=fad48ae93e9e02bcf7e386d48a6d7da7&sv=3)

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FtNCJeODAVk9m4TWE9WwE%252Fimage.png%3Falt%3Dmedia%26token%3Dc44e5a18-3dfa-4801-8c3d-999b25ce27ac&width=768&dpr=3&quality=100&sign=aeee6e160d270037adeb58fc72bc0b46&sv=3)

![](https://ctf.krauq.com/~gitbook/image?url=https%3A%2F%2F319637167-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fpfs5GbEFUvNmvw1Ekwmu%252Fuploads%252FNSBATJa4BwdkGDXU5ktJ%252Fimage.png%3Falt%3Dmedia%26token%3D26740119-37a1-44d3-808f-2bb663533713&width=768&dpr=3&quality=100&sign=87a36f44e08b3f72c732b178b3d85a45&sv=3)

[PreviousCubeCTF 2025](https://ctf.krauq.com/cubectf-2025)[NextBCACTF 2024](https://ctf.krauq.com/bcactf-2024)

Last updated 1 year ago
