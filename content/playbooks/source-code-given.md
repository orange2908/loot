---
title: "Playbook - The Challenge Gave Me Source Code"
category: misc
subcategory: triage
type: playbook
tags: [source-code-given, code-review, where-to-start, stuck, grep-list, audit, sink, taint, dockerfile, handout, what-attack, python, php, javascript, java, go, c, rust, ruby, solidity]
summary: "The review order for any handout source plus a per-language grep list of dangerous sinks."
when_to_use:
  - "The challenge handout includes the application source"
  - "You have a Dockerfile / docker-compose and want to know what the deployment tells you"
  - "You need to find the one deliberate bug in otherwise normal-looking code"
related: [web-triage, crypto-triage, pwn-triage, regex-recipes, linux-useful-paths]
---

## TL;DR - the review order

1. **Find the flag.** Where does it live and who reads it?
2. **Read the deployment.** `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `xinetd.conf`, `Makefile`.
3. **Map the entry points.** Routes, menu items, `main()`, message handlers.
4. **Find what the author wrote themselves.** CTF bugs are in custom code, not in dependencies.
5. **Grep the sinks.** (Section 4.)
6. **Trace one input from entry to sink.**
7. **Check what is missing.** An absent auth check, an absent length check, an absent `free(p); p=NULL`.

Do not read the code top to bottom. Read it backwards from the flag.

```sh
# step 1, mechanically
grep -rniE 'flag|FLAG' . | grep -vE '\.min\.js|node_modules|vendor|\.map' | head -40
cat Dockerfile docker-compose.yml 2>/dev/null
git log --oneline -20 2>/dev/null
```

---

## Section 1 - What the deployment files tell you

| File / line | What it tells you |
|---|---|
| `COPY flag.txt /flag.txt` | the flag is a file at a known path -> you need arbitrary file read or RCE |
| `ENV FLAG=...` / `environment: - FLAG=` | the flag is an env var -> `/proc/self/environ`, `printenv`, `os.environ`, an error page |
| `RUN chmod 400 /flag && chown root` | you need privilege escalation or a setuid binary |
| `FROM python:3.8` (old) | the version may matter: check for a known CVE in that runtime |
| `FROM ubuntu:18.04` + a libc | tells you the glibc version for heap exploitation |
| `USER ctf` | you are not root; look for a setuid binary or a suid helper |
| `EXPOSE 80` but the app listens elsewhere | there is a proxy in front: header-based bypasses matter |
| Two services in compose (`app` + `db` + `internal`) | SSRF target names: `http://internal:8080` |
| `socat`/`xinetd` wrapper | the binary runs per-connection, so ASLR is re-randomised each time; but a `fork` server keeps it |
| `ulimit -s` or `sysctl` tweaks | the author disabled something on purpose |
| A `requirements.txt` pinning an old library | look up that exact version's CVE |
| `/readflag` binary present | you need to execute it, not read the file |
| `timeout 60` in the entrypoint | your exploit has a time budget |
| A healthcheck hitting an endpoint | that endpoint exists even if undocumented |

```sh
# reconstruct the exact runtime
docker build -t chal . && docker run --rm -it -p 1337:1337 chal
# or just read what it will run
grep -rn 'CMD\|ENTRYPOINT\|command:' Dockerfile docker-compose.yml
```

---

## Section 2 - Map the entry points

```sh
# Web routes
grep -rnE '@(app|bp|router)\.(route|get|post|put|delete)|app\.(get|post|use)\(|Route::|Router::|@(Get|Post|Request)Mapping|http\.HandleFunc|urlpatterns' . | head -60
# CLI / menu
grep -rnE 'case *[0-9]|switch *\(|argv\[|sys\.argv|ArgumentParser|flag\.String' . | head -40
# Message/event handlers
grep -rnE 'on\(|addEventListener|@app\.(before|after)_request|socket\.on|consume|subscribe' . | head -40
```

For each entry point write down three things: **who can reach it** (auth?), **what it reads from the user**, and **what it does with it**. The bug is where those three do not line up.

---

## Section 3 - The "what is custom" heuristic

CTF authors do not plant bugs in Django or OpenSSL. They plant them in:

| Custom thing | Almost always the bug |
|---|---|
| A hand-rolled session/token format | forgeable; check the signature and the key |
| A hand-rolled "encryption" | reversible; write the inverse |
| A hand-rolled sanitiser (blocklist) | bypass it: case, encoding, nesting, unicode, a missed character |
| A hand-rolled parser | parser differential vs the real one |
| A hand-rolled path check (`if "../" in p`) | `....//`, `%2e%2e%2f`, absolute path, symlink |
| A hand-rolled comparison (`==` on secrets) | timing, or type juggling |
| A hand-rolled rate limiter | race condition |
| A `# NOTE:` or `# this is safe because` comment | it is not safe |
| A dependency vendored and modified | diff it against the real release |
| A function that exists but is never called | it is called by the bug you have not found yet |

```sh
# diff a vendored dependency against upstream
pip download requests==2.31.0 -d /tmp/up --no-deps && diff -ru /tmp/up/requests ./vendor/requests
```

---

## Section 4 - Grep list by language

### Python
```sh
# code execution
grep -rnE 'eval\(|exec\(|compile\(|__import__|getattr\(|setattr\(|globals\(\)|locals\(\)' --include='*.py' .
grep -rnE 'os\.(system|popen|spawn)|subprocess\.(run|call|Popen|check_output)|shell *= *True|commands\.' --include='*.py' .
# deserialization
grep -rnE 'pickle\.(load|loads)|cPickle|marshal\.loads|yaml\.load\((?!.*Loader=SafeLoader)|dill|shelve|jsonpickle|torch\.load' --include='*.py' -P .
# template injection
grep -rnE 'render_template_string|Template\(|from_string|jinja2\.|Environment\(' --include='*.py' .
# format-string / attribute traversal
grep -rnE '\.format\(|%\s*\(|f["\x27][^"\x27]*\{[^}]*\}' --include='*.py' .
# SQL
grep -rnE 'execute\(\s*["\x27].*(%s|%d|\+|\.format|f["\x27])|\.raw\(|text\(' --include='*.py' .
# path traversal / file read
grep -rnE 'open\(|send_file|send_from_directory|os\.path\.join|shutil|Path\(' --include='*.py' .
# SSRF
grep -rnE 'requests\.(get|post)|urllib|urlopen|httpx|aiohttp|socket\.create_connection' --include='*.py' .
# weak crypto / randomness
grep -rnE 'random\.|md5|sha1\(|DES|ECB|hashlib\.new|\bseed\(|time\.time\(\)' --include='*.py' .
# auth gaps
grep -rnE '@login_required|@require|is_admin|session\[|current_user|jwt' --include='*.py' .
```
Python-specific CTF classics: `pickle.loads` on user data (instant RCE), `yaml.load` without `SafeLoader`, `eval` behind a character blocklist (pyjail), `str.format` on a user-controlled format string (`{0.__class__.__init__.__globals__}`), `subprocess(..., shell=True)`, `assert` used for security (stripped with `-O`).

### PHP
```sh
grep -rnE 'eval|assert|preg_replace\s*\(.*/e|create_function|call_user_func|\$\$|\$\{' --include='*.php' .
grep -rnE 'system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|`' --include='*.php' .
grep -rnE 'unserialize|__wakeup|__destruct|__toString|__invoke|__call|phar://' --include='*.php' .
grep -rnE 'include|include_once|require|require_once|file_get_contents|fopen|readfile|file_put_contents|copy|move_uploaded_file' --include='*.php' .
grep -rnE 'extract\(|parse_str|import_request_variables|\$_REQUEST' --include='*.php' .
grep -rnE '[^=!<>]==[^=]|in_array\(|switch\s*\(|strcmp|md5\(|sha1\(|hash\(' --include='*.php' .
grep -rnE 'mysqli?_query|->query\(|->exec\(|PDO' --include='*.php' .
```
PHP classics: loose comparison (`"0e1" == "0e2"` -> true, `"abc" == 0` on PHP 7), `strcmp($a, [])` returns NULL (NULL == 0), `in_array($x, $arr)` without strict mode, `unserialize` + a POP chain (phpggc), `phar://` deserialization via any filesystem function, `preg_replace` with `/e`, `extract($_GET)` overwriting variables, `include $_GET['p']` with `php://filter/convert.base64-encode/resource=`.

### JavaScript / Node
```sh
grep -rnE 'eval\(|new Function|vm\.(run|compileFunction)|vm2|child_process|exec\(|execSync|spawn\(' --include='*.js' --include='*.ts' .
grep -rnE '__proto__|constructor\s*\[|prototype\s*\[|_\.(merge|mergeWith|set|defaultsDeep)|Object\.assign\(' --include='*.js' --include='*.ts' .
grep -rnE 'JSON\.parse|node-serialize|serialize-javascript|funcster' --include='*.js' .
grep -rnE 'innerHTML|outerHTML|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|v-html|\$\(.*\)\.(html|append)' --include='*.js' --include='*.jsx' --include='*.vue' .
grep -rnE 'jwt\.(sign|verify|decode)|algorithms *:|ignoreExpiration|complete *: *true' --include='*.js' .
grep -rnE '\$where|\$ne|\$regex|\$gt|find\(\s*req\.|findOne\(\s*req\.' --include='*.js' .
grep -rnE 'path\.join|fs\.(readFile|createReadStream|writeFile)|res\.sendFile|express\.static' --include='*.js' .
grep -rnE 'res\.redirect|location *=|window\.open|postMessage|addEventListener\([\x27"]message' --include='*.js' .
```
Node classics: prototype pollution reaching a template engine or `child_process` options (`{shell: ...}`, `NODE_OPTIONS`), `vm`/`vm2` sandbox escape via `this.constructor.constructor("return process")()`, JWT `algorithms` not pinned, NoSQL operators accepted from `req.body` because `extended: true` body parsing makes objects, `express.static` before auth middleware, unhandled `__proto__` in a query string (`?a[__proto__][x]=1`).

### Java
```sh
grep -rnE 'readObject|ObjectInputStream|XMLDecoder|readValue|enableDefaultTyping|@JsonTypeInfo|Yaml\.load|readUnshared' --include='*.java' .
grep -rnE 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ScriptEngineManager|GroovyShell|Ognl|SpelExpressionParser|MVEL' --include='*.java' .
grep -rnE 'createQuery|createNativeQuery|Statement|executeQuery\(.*\+' --include='*.java' .
grep -rnE 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|Unmarshaller|XPath' --include='*.java' .
grep -rnE 'new File\(|Paths\.get\(|getResourceAsStream|FileInputStream' --include='*.java' .
grep -rnE 'InitialContext|lookup\(|rmi://|ldap://|jndi' --include='*.java' .
```
Java classics: `ObjectInputStream.readObject` + a gadget on the classpath (ysoserial: CommonsCollections, Spring, Hibernate), Jackson polymorphic deserialization, XXE because the parser factory was not hardened, JNDI injection (`ldap://attacker/a` -> Log4Shell), EL/OGNL/SpEL in an error message or a filter parameter.

### Go
```sh
grep -rnE 'text/template|template\.(HTML|JS|URL)|exec\.Command|os/exec|syscall\.' --include='*.go' .
grep -rnE 'fmt\.Sprintf\(\s*"[^"]*(SELECT|INSERT|UPDATE|DELETE)' --include='*.go' .
grep -rnE 'filepath\.Join|http\.Dir|http\.ServeFile|os\.Open|ioutil\.ReadFile' --include='*.go' .
grep -rnE 'json\.Unmarshal|yaml\.Unmarshal|gob\.Decode' --include='*.go' .
grep -rnE 'httputil\.NewSingleHostReverseProxy|http\.Get|http\.Client' --include='*.go' .
```
Go classics: `text/template` instead of `html/template` (no escaping), `filepath.Join` not preventing traversal when the base is attacker-influenced, integer conversions between `int` and `int32`, a `nil` map write panic used as a DoS, goroutine races on a shared map.

### Ruby
```sh
grep -rnE '\beval\b|instance_eval|class_eval|send\(|__send__|public_send|const_get|constantize|Kernel\.' --include='*.rb' .
grep -rnE 'Marshal\.load|YAML\.load|Psych\.load|JSON\.load|ERB\.new' --include='*.rb' .
grep -rnE 'system\(|%x\(|`|Open3|IO\.popen|exec\(' --include='*.rb' .
grep -rnE 'render\s+(file|inline|text|:file)|params\[' --include='*.rb' .
grep -rnE 'find_by_sql|where\(\s*"|execute\(' --include='*.rb' .
```

### C / C++
```sh
grep -rnE '\b(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|alloca)\s*\(' --include='*.c' --include='*.cpp' --include='*.h' .
grep -rnE '\b(memcpy|memmove|strncpy|strncat|snprintf|read|recv)\s*\(' --include='*.c' --include='*.cpp' .
grep -rnE 'printf\s*\(\s*[a-zA-Z_]' --include='*.c' .           # printf(var) = format string
grep -rnE 'malloc|calloc|realloc|free\(' --include='*.c' --include='*.cpp' .
grep -rnE 'system\(|popen\(|execl|execve|fork\(' --include='*.c' .
grep -rnE '\[\s*i\s*\]|\[\s*idx|\[\s*index' --include='*.c' .   # unchecked indexing
grep -rnE '\b(int|short|char)\s+\w+\s*=.*(len|size|count)' --include='*.c' .  # signed size
```
C classics: signed/unsigned confusion on a size, off-by-one in a loop bound (`<=`), `free` without nulling, a `char buf[N]` next to a length variable, `strncpy` that does not null-terminate, `printf(user)`.

### Solidity
```sh
grep -rnE 'call\{value|\.call\(|delegatecall|selfdestruct|tx\.origin|block\.(timestamp|number|difficulty)|blockhash' --include='*.sol' .
grep -rnE 'unchecked|assembly|transfer\(|send\(' --include='*.sol' .
grep -rnE 'public|external' --include='*.sol' . | grep -iE 'withdraw|mint|owner|init'
```
`ctfbrain search web3-audit`

---

## Section 5 - Trace the taint

For the one entry point that looks most promising:

```
USER INPUT
  |  where does it enter?  (req.body.x, argv[1], the socket read, a cookie)
  v
TRANSFORMS
  |  every function it passes through. write them down.
  |  does anything validate length? type? charset? encoding?
  |  is the validation done BEFORE or AFTER a decode/normalisation? (order bugs)
  v
SINK
     eval / exec / query / open / printf / memcpy / deserialize / render
```

Questions that find the bug:
- Is the length checked against the buffer that is actually written to, or a different one?
- Is the validation on the decoded value or the raw value?
- Can the value be an array/object instead of a string?
- Can it be negative? Can it be `0`? Can it be huge? Can it be empty?
- Is the check `if (x)` where `x = 0` is legitimate?
- Is there a TOCTOU gap between the check and the use?
- Does an exception path skip the cleanup?

---

## Section 6 - Diffing an open-source project

If the handout is a fork of a real project, the bug is in the diff.

```sh
# clone upstream at the same version and diff
git clone --depth 50 https://github.com/<org>/<repo> /tmp/up
diff -ru /tmp/up ./handout | grep -vE '^Only in' | head -200
# if it is a git repo already
git log --oneline --all
git diff $(git rev-list --max-parents=0 HEAD) HEAD --stat
```
If `.git` is present, always run `git log -p` - CTF authors leave the flag in a previous commit more often than you would think.

---

## Section 7 - Category routing

| The source is... | Go to |
|---|---|
| A web app | `ctfbrain search web-triage` |
| A crypto script | `ctfbrain search crypto-triage` |
| C with a socket loop | `ctfbrain search pwn-triage` |
| A Solidity contract | `ctfbrain search web3-audit` |
| A sandbox/jail | `ctfbrain search pyjail` |
| A parser/serializer | look for differentials and recursion limits |
| A "just find the password" script | `ctfbrain search z3` |

Still stuck after a full pass: `ctfbrain search stuck`
