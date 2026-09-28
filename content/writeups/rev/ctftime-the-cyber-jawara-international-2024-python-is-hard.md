---
title: "Python is Hard - The Cyber Jawara International 2024"
category: "rev"
subcategory: "symbolic-execution"
type: "writeup"
tags: ["rev", "z3", "pyjail", "base64", "python", "hard", "symbolic-execution", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "![ Sign in via Google  ](https://hackmd.io/auth/google)  ![ Sign in via Facebook  ](https://hackmd.io/auth/facebook)  ![ Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter)  ![ Sign in via GitHu"
source:
  name: "CTFtime writeup #39590"
  url: "https://ctftime.org/writeup/39590"
original_source: "https://hackmd.io/@yqroo/rJcg3xTlJx"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Python is Hard"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Python is Hard
- **Author team:** dimas fans club
- **CTFtime:** <https://ctftime.org/writeup/39590>
- **Original writeup:** <https://hackmd.io/@yqroo/rJcg3xTlJx>

---
# Python is Hard Last week, I participated in the Cyber Jawara International CTF 2024 with my university’s merged team. During the competition, I managed to solve only one reversing challenge, as I was more focused on a Pyjail challenge (which I didn’t manage to solve, and no one solved it until the CTF was over). Despite my focus, I found all the reversing challenges quite difficult overall. ## Understand js2py VM We are given python file that looks like compressed with zlib and encoded in base64, after recovering the source code we'll see js2py VM. chall.py (with some adjustment) ```python= import pyjsparser from js2py.internals.space import Space from js2py.internals import fill_space from js2py.internals.byte_trans import ByteCodeGenerator from js2py.internals.code import Code from js2py.internals.simplex import * from js2py.internals.opcodes import * a = ByteCodeGenerator(Code(debug_mode=True)) s = Space() a.exe.space = s s.exe = a.exe d = pyjsparser.parse("") a.emit(d) fill_space.fill_space(s, a) a.exe.tape = [LOAD_UNDEFINED(), LOAD_STRING(input("Input flag: "),), STORE('inp',), POP(), LOAD_ARRAY(0,), STORE('a',), POP(), LOAD_ARRAY(0,), STORE('b',), POP(), LOAD_ARRAY(0,), STORE('c',), POP(), LOAD_ARRAY(0,), STORE('d',), POP(), LOAD_NUMBER(0.0,), STORE('i',), POP(), JUMP(3,), ...altered because of long text... LABEL(21,), JUMP_IF_FALSE(19,), POP(), LOAD('console',), LOAD_STRING('congrats',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('log',), JUMP(20,), LABEL(19,), POP(), LOAD('console',), LOAD_STRING('failed',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('log',), LABEL(20,)] a.exe.compile() a.exe.run(a.exe.space.GlobalObj) ``` By reading the opcode, we could intuitively imagine what the JS code will be like, but for the sake of correctness, we could actually look at the actual implementation at GitHub. https://github.com/PiotrDabkowski/Js2Py If we look at the github page we could see how they generate those opcode : ![image](https://hackmd.io/_uploads/S1EpeZTlkx.png) So after reading the opcode from the challenge itself i try to mimic it by creating JS code and compare it with the actual opcode. We could see some pattern on the opcode so once you get it it was pretty easy to convert back to JS. Like for this example this opcode is a for loop ```python= LABEL(1,), LOAD_NUMBER(4.0,), STORE_OP('i', '+'), POP(), LABEL(3,), LOAD('i',), LOAD_NUMBER(36.0,), BINARY_OP('<',), JUMP_IF_FALSE(2,), LOAD_NUMBER(0.0,), STORE('tmp',), POP(), LOAD_NUMBER(0.0,), STORE('j',), POP(), JUMP(6,), LABEL(4,), POSTFIX(1, -1, 'j'), POP(), LABEL(6,), LOAD('j',), LOAD_NUMBER(4.0,), BINARY_OP('<',), JUMP_IF_FALSE(5,), POP(), LOAD('inp',), LOAD('i',), LOAD('j',), BINARY_OP('+',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('charCodeAt',), LOAD('j',), LOAD_NUMBER(8.0,), BINARY_OP('*',), BINARY_OP('<<',), STORE_OP('tmp', '|'), JUMP(4,), LABEL(5,), POP(), LOAD('a',), LOAD('tmp',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('push',), JUMP(1,), ``` And this how they look like in js ```javascript= for (var i = 0; i < 36; i+=4) { var tmp = 0; for (var j = 0; j < 4; j++) { tmp |= inp.charCodeAt(i + j) << (8 * j); } a.push(tmp); } ``` This what i have at the end ```javascript= for (var i = 0; i < 36; i+=4) { var tmp = 0; for (var j = 0; j < 4; j++) { tmp |= inp.charCodeAt(i + j) << (8 * j); } a.push(tmp); } for (var i = 0; i < 36; i+=2) { var tmp = 0; for (var j = 0; j < 2; j++) { tmp |= inp.charCodeAt(i + j) << (8 * j); } b.push(tmp); } for (var i = 0; i < 36; i+=1) { var tmp = 0; for (var j = 0; j < 1; j++) { tmp |= inp.charCodeAt(i + j) << (8 * j); } c.push(tmp); } ``` There's some equation that i don't write back to JS because i directly try to solve the equation with z3. ## POC After knowing that this is just a z3 because there's lot of equation and check i write this solve script sol.py : ```python= from z3 import * inp = [BitVec(f'inp_{i}', 32) for i in range(36)] a = [] b = [] c = [] for i in range(0, 36, 4): tmp = BitVecVal(0, 32) for j in range(4): tmp |= inp[i + j] << (8 * j) a.append(tmp) for i in range(0, 36, 2): tmp = BitVecVal(0, 32) for j in range(2): tmp |= inp[i + j] << (8 * j) b.append(tmp) for i in range(36): tmp = inp[i] c.append(tmp) constraints = [ (a[3] + (b[5] + b[15]) ^ (c[12] + c[5] - c[28]) ^ c[19] ^ 1337) == 1634073638, (a[8] ^ (b[16] ^ b[7]) ^ (c[2] + c[33] + c[22] + c[8] - 1337)) == -892560024, (a[2] + ((b[10] + b[2]) ^ (c[3] + c[20]) ^ (c[7] - c[25] + 1337))) == 1767917691, (a[5] + ((b[14] - b[13] + c[10]) ^ (c[11] - c[29]) ^ (c[13] + 1337))) == 1948741702, (a[4] + ((b[4] - b[17] + c[1]) ^ (c[16] - c[27] - c[26]) ^ 1337)) == 1767849594, (a[1] - ((b[6] - b[12] + c[18]) ^ (c[4] - c[17]) ^ c[23] ^ 1337)) == 1769100975, (a[0] ^ ((b[0] ^ (b[1] - c[9])) ^ (c[21] - c[30] + c[32] + 1337))) == 1635149008, (a[6] + ((b[8] - b[9]) ^ (c[31] - c[14] - c[6] - c[35] - 1337))) == 1601459038, (a[7] + ((b[3] - b[11] - c[15] + c[0] - c[24]) ^ (c[34] - 1337))) == 809005425 ] solver = Solver() solver.add(constraints) # solver.add(inp[0] == ord('j')) solver.add(inp[1] == ord('a')) for char in inp: solver.add(char > 32, char < 0x7f) if solver.check() == sat: model = solver.model() for i in range(36): print(chr(model[inp[i]].as_long()), end='') else: print("No solution found.") ``` But i think i got one of the equation wrong since it returns me an invalid flag ``` j^varcrist_iw_easy_isn't_it_bc80c635 ``` or ``` `avascript_iu_eauy_ion'tait_^c80c935 ``` As we can see we fucked up some chars, but we could do some guess work from it. In the end it was ``` javascript_is_easy_isn't_it_bc80c935 ```

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
