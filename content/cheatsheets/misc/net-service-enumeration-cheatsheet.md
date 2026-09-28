---
title: "Service Enumeration Cheatsheet - First 5 Commands Per Port"
category: misc
subcategory: network-services
type: cheatsheet
tags: [enumeration, netexec, smbclient, snmpwalk, rpcclient, ldapsearch, redis-cli, ftp, ssh, smtp, network-services, per-port, recon]
summary: "For each common open port: the first five commands to run, so you never stare at an nmap result wondering where to start."
related: [net-smb, net-snmp-nfs-rpc-ldap, net-nosql-services, net-legacy-services, net-mail-services]
---

## 21 FTP

```bash
nmap -p21 --script "ftp-anon,ftp-syst,ftp-vsftpd-backdoor" -sV 10.10.10.5   # scripts + backdoor check
ftp -inv 10.10.10.5                                                        # try anonymous login
curl -s ftp://anonymous:anonymous@10.10.10.5/                              # list root anonymously
wget -r --no-passive-ftp ftp://anonymous:anonymous@10.10.10.5/             # mirror if readable
nc -nv 10.10.10.5 21                                                       # grab the banner/version
```

## 22 SSH

```bash
nc -nv 10.10.10.5 22                       # banner/version
ssh-audit 10.10.10.5                        # algorithm/version audit -> CVE match
ssh-keyscan 10.10.10.5                       # host key (detect reuse)
ssh user@10.10.10.5                          # try known/weak creds
nmap -p22 --script ssh2-enum-algos,ssh-auth-methods 10.10.10.5   # auth methods
```

## 23 Telnet

```bash
nc -nv 10.10.10.5 23                                        # banner
telnet 10.10.10.5                                            # try default/weak creds
nmap -p23 --script "telnet-encryption,telnet-ntlm-info" -sV 10.10.10.5   # encryption/NTLM info
hydra -L users.txt -P pass.txt telnet://10.10.10.5           # brute (careful)
```

## 25 / 465 / 587 SMTP

```bash
nc -nv 10.10.10.5 25                                         # banner then EHLO
smtp-user-enum -M RCPT -U users.txt -t 10.10.10.5            # user enumeration
nmap -p25 --script "smtp-commands,smtp-open-relay,smtp-enum-users" 10.10.10.5   # relay + users
openssl s_client -connect 10.10.10.5:587 -starttls smtp      # STARTTLS
swaks --to a@t --from b@x --server 10.10.10.5 --header 'Subject: t' --body t   # send test mail
```

## 53 DNS

```bash
dig @10.10.10.5 version.bind CHAOS TXT              # server version
dig @10.10.10.5 NS target.ctf                        # nameservers
dig axfr target.ctf @10.10.10.5                      # zone transfer
dig ANY target.ctf @10.10.10.5                       # try any records
dnsrecon -d target.ctf -n 10.10.10.5 -a              # automated AXFR + brute
```

## 80 / 443 HTTP(S)

```bash
whatweb -a3 http://10.10.10.5                        # fingerprint stack
curl -sI http://10.10.10.5/                           # headers / redirects
curl -s http://10.10.10.5/robots.txt                  # robots + sitemap hints
ffuf -u http://10.10.10.5/FUZZ -w raft-medium-directories.txt -ac   # content discovery
nmap -p80,443 --script "http-enum,http-title,ssl-cert" 10.10.10.5   # NSE + cert SAN names
```

## 88 Kerberos

```bash
nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='CORP.LOCAL' 10.10.10.5   # user enum
kerbrute userenum -d corp.local --dc 10.10.10.5 users.txt   # user enumeration
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.5   # AS-REP roast
nmap -p88 -sV 10.10.10.5                              # confirm it is a DC
```

## 110 / 995 POP3

```bash
nc -nv 10.10.10.5 110                                 # banner
openssl s_client -connect 10.10.10.5:995 -quiet       # TLS connect
nmap -p110 --script pop3-capabilities,pop3-ntlm-info 10.10.10.5   # capabilities
printf 'USER jdoe\r\nPASS pass\r\nLIST\r\nQUIT\r\n' | nc 10.10.10.5 110   # login + list
```

## 111 RPC / rpcbind

```bash
rpcinfo -p 10.10.10.5                                 # registered programs
showmount -e 10.10.10.5                                # NFS exports
rpcclient -U '' -N 10.10.10.5                          # null-session RPC
nmap -p111 --script "rpcinfo,nfs-showmount" 10.10.10.5 # NSE
```

## 135 / 139 / 445 SMB / MSRPC

```bash
netexec smb 10.10.10.5                                 # OS/domain/signing
smbclient -L //10.10.10.5 -N                            # null-session share list
enum4linux-ng -A 10.10.10.5                             # full null-session enum
smbmap -H 10.10.10.5 -u '' -p ''                        # per-share R/W
nmap -p445 --script "smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010" 10.10.10.5   # NSE + MS17-010
```

## 143 / 993 IMAP

```bash
nc -nv 10.10.10.5 143                                  # banner
openssl s_client -connect 10.10.10.5:993 -quiet        # TLS connect
nmap -p143 --script imap-capabilities,imap-ntlm-info 10.10.10.5   # capabilities
printf 'a LOGIN jdoe pass\r\na LIST "" "*"\r\na LOGOUT\r\n' | nc 10.10.10.5 143   # login + list
```

## 161 SNMP (UDP)

```bash
onesixtyone 10.10.10.5 public private                  # community brute
snmpwalk -v2c -c public 10.10.10.5                      # full walk
snmp-check -c public 10.10.10.5                         # readable summary
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.25.4.2.1.5   # process command lines (creds!)
nmap -sU -p161 --script "snmp-info,snmp-processes" 10.10.10.5   # NSE
```

## 389 / 636 / 3268 LDAP

```bash
ldapsearch -x -H ldap://10.10.10.5 -s base namingContexts   # base DN
ldapsearch -x -H ldap://10.10.10.5 -b 'DC=corp,DC=local'    # anonymous dump
nmap -p389 --script "ldap-rootdse,ldap-search" 10.10.10.5   # NSE
ldapdomaindump -u 'corp.local\jdoe' -p pass 10.10.10.5 -o ldd/   # authenticated dump
windapsearch -d corp.local --dc-ip 10.10.10.5 -u jdoe -p pass -U   # users
```

## 1433 MSSQL

```bash
nmap -p1433 --script ms-sql-info,ms-sql-empty-password 10.10.10.5   # info + empty sa
netexec mssql 10.10.10.5 -u sa -p '' --local-auth            # try sa blank
impacket-mssqlclient sa:''@10.10.10.5                        # connect
netexec mssql 10.10.10.5 -u sa -p pass -x 'whoami'           # xp_cmdshell exec
```

## 2049 NFS

```bash
showmount -e 10.10.10.5                                # exports
sudo mount -t nfs -o nolock,vers=3 10.10.10.5:/export /mnt/nfs   # mount
ls -la /mnt/nfs                                         # check ownership/UIDs
nmap -p2049 --script "nfs-ls,nfs-showmount,nfs-statfs" 10.10.10.5   # NSE
```

## 3306 MySQL

```bash
nmap -p3306 --script mysql-info,mysql-empty-password 10.10.10.5   # info + blank root
mysql -h 10.10.10.5 -u root                              # root blank password
mysql -h 10.10.10.5 -u root -proot                        # root:root
netexec mysql 10.10.10.5 -u root -p ''                    # validate creds
```

## 3389 RDP

```bash
nmap -p3389 --script rdp-ntlm-info 10.10.10.5            # hostname/domain leak
netexec rdp 10.10.10.5 -u users.txt -p 'Winter2024!'      # spray (careful: lockout)
xfreerdp /u:user /p:pass /v:10.10.10.5 /cert:ignore       # connect
```

## 5432 PostgreSQL

```bash
nmap -p5432 --script pgsql-brute 10.10.10.5              # brute
psql -h 10.10.10.5 -U postgres                            # postgres:postgres
netexec postgres 10.10.10.5 -u postgres -p postgres       # validate
```

## 5985 / 5986 WinRM

```bash
netexec winrm 10.10.10.5 -u user -p pass                 # validate creds
evil-winrm -i 10.10.10.5 -u user -p pass                  # shell
evil-winrm -i 10.10.10.5 -u user -H NTHASH                # pass-the-hash
```

## 6379 Redis

```bash
redis-cli -h 10.10.10.5 ping                             # auth required?
redis-cli -h 10.10.10.5 INFO                              # version/config
redis-cli -h 10.10.10.5 KEYS '*'                          # dump keys
redis-cli -h 10.10.10.5 CONFIG GET dir                    # writable dir -> RCE path
```

## 9200 Elasticsearch / 5984 CouchDB / 27017 Mongo / 11211 Memcached

```bash
curl -s 'http://10.10.10.5:9200/_cat/indices?v'          # elastic indices
curl -s http://10.10.10.5:5984/_all_dbs                   # couch databases
mongosh "mongodb://10.10.10.5:27017" --eval 'db.adminCommand({listDatabases:1})'   # mongo dbs
printf 'stats\r\n' | nc -q1 10.10.10.5 11211              # memcached stats
```
