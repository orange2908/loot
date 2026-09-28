---
title: "whats-your-number - JerseyCTF V"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "union-select", "wireshark", "scapy", "nmap", "jerseyctf-v", "ctf-writeup"]
summary: "1\\. Load the site. To login, SQL injection is needed."
source:
  name: "CTFtime writeup #40128"
  url: "https://ctftime.org/writeup/40128"
ctf:
  name: "JerseyCTF V"
  challenge: "whats-your-number"
---

## Metadata

- **CTF:** JerseyCTF V
- **Task:** whats-your-number
- **Author team:** Highlander Hackers
- **CTFtime:** <https://ctftime.org/writeup/40128>

---
1\. Load the site. To login, SQL injection is needed. From analyzing the provided code, you can derive what is needed for it.  
1\. Being the password is hashed, create a hash for the password `password`:  
* `php -r 'echo(password_hash("password", PASSWORD_DEFAULT));'`  
* `$2y$10$p.ldrVih8Mlgv1jqphZjFuPTXLFjJipgXKPEFW1WUB0M5rMx3QLt.`  
2\. Example SQL payload:

```sql  
' UNION SELECT 1 AS id, 'admin' as username, '$2y$10$k0skuQFoUC4vfKRYgGbUdeUrC7Fl3ik9WBKRW9uvZb5h7hzhX4Ale' as password;--   
```

3\. The SQL payload would go in the username field, and `password` for password.

2\. Once logged in, there will be an error (`You must be within the internal network to use this function.`), but you now have a session token.

3\. The server is vulnerable to a TCP sequence number attack. The description somewhat points to something happening at the transport layer.  
* An easy way to check is with `sudo nmap -v -A -Pn [whats-your-number.aws.jerseyctf.com](http://whats-your-number.aws.jerseyctf.com)`, which returns `TCP Sequence Prediction: Difficulty=0 (Trivial joke)`. Although Wireshark can also be used.

4\. The user now needs to register an API key, but they need to spoof the source address of `1.2.3.4` (`127.0.0.1` would not go over the internet). Due to the TCP sequence numbers being predictable, this can be done with scapy. A full solve script at this point is available in [[solve.py](http://solve.py)](./challenge/configurationFiles/[solve.py](http://solve.py)). The session key in the HTTP POST request needs to be updated to match yours. The script:

* Sets up a TCP connection (although responses can't be received). Since the sequence numbers are predictable, the source can be spoofed.  
* Sends the request to register the API key.  
* Uses the API key to use the `/api/runCommand.php` to curl the `/api/getFlag.php` from localhost and then send it to a webhook (this address needs to be changed).  
* `sudo python3 [solve.py](http://solve.py) <ip of relay or challenge> 80 <1.2.3.4 - or actual IP if using relay> <random source port>`  
* As stated in the challenge description, the provided relay may need to be used. This is likely the case unless the user has a connection without source checking *and* has control over their NAT (residential connection users most likely). If using the relay, un-NATted public IP access may still be necessary depending on how the NAT is implemented. DigitalOcean is one of the providers that supply this.
