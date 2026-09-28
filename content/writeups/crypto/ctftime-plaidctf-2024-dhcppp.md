---
title: "DHCPPP - PlaidCTF 2024"
category: "crypto"
subcategory: "mac"
type: "writeup"
tags: ["crypto", "poly1305", "chacha20", "dhcppp", "mac", "plaidctf", "plaidctf-2024", "2024", "ctf-writeup"]
summary: "Investigation Title. DHCPPP"
source:
  name: "CTFtime writeup #39060"
  url: "https://ctftime.org/writeup/39060"
original_source: "https://sectt.github.io/writeups/Plaid24/DHCPPP/README"
ctf:
  name: "PlaidCTF 2024"
  year: 2024
  challenge: "DHCPPP"
---

## Metadata

- **CTF:** PlaidCTF 2024
- **Task:** DHCPPP
- **Author team:** STT
- **CTFtime:** <https://ctftime.org/writeup/39060>
- **Original writeup:** <https://sectt.github.io/writeups/Plaid24/DHCPPP/README>

---
DHCPPP – PlaidCTF 2024

## Given

```
    Investigation Title. DHCPPP
    Reporter. anish
    Type. Dance Competition
    Description. The local latin dance company is hosting a comp. They have a million-dollar wall of lava lamps and prizes so big this must be a once-in-a-lifetime opportunity.
    Hypotheses. It's not DNS // There's no way it's DNS // It was DNS
    Notes.
    nc dhcppp.chal.pwni.ng 1337
```

## Source

[here](https://sectt.github.io/writeups/Plaid24/DHCPPP/source.py)

## TL;DR

  * We are presented with a server that uses `ChaCha20-Poly1305`. The goal is to change the value of the variable `dns.nameservers` so that the request with the flag is done to a server controlled by us. However, we can only do that by sending an encrypted message with a valid authentication tag.

  * The `key` and the `nonce` are both reused, allowing us to create valid tags for any message and therefore encrypt arbitrary messages.


## Code Analysis

This server allows us to connect to a TCP connection and send packets, that will be processed by the `DHCPServer` and `FlagServer`, and the responses are printed out.

```
    if __name__ == "__main__":
        dhcp = DHCPServer()
        flagserver = FlagServer(dhcp)
    
        while True:
            pkt = bytes.fromhex(input("> ").replace(" ", "").strip())
    
            out = dhcp.process_pkt(pkt)
            if out is not None:
                print(out.hex())
    
            out = flagserver.process_pkt(pkt)
            if out is not None:
                print(out.hex())
```

### DHCPServer

The server constructor defines a list of IP addresses, a MAC address, a gateway IP, among others.

```
    def __init__(self):
            self.leases = []
            self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
            self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
            self.gateway_ip = "192.168.1.1"
    
            self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))
```

To process each DHCP packet, we use the function `process_pkt`.

```
    def process_pkt(self, pkt):
            assert pkt is not None
    
            src_mac = pkt[:6]
            dst_mac = pkt[6:12]
            msg = pkt[12:]
    
            if dst_mac != self.mac:
                return None
    
            if src_mac == self.mac:
                return None
    
            if len(msg) and msg.startswith(b"\x01"):
                # lease request
                dev_name = msg[1:]
                lease_resp = self.get_lease(dev_name)
                return (
                    self.mac +
                    src_mac + # dest mac
                    lease_resp
                )
            else:
                return None
```

From the code above we immediately notice that in order to get a response, `msg` must start with `\x01`. The content of `dev_name` is then passed to the function `get_lease`.

```
    def get_lease(self, dev_name):
            if len(self.ips) != 0:
                ip = self.ips.pop(0)
                self.leases.append((ip, dev_name, time.time(), []))
            else:
                # relinquish the oldest lease
                old_lease = self.leases.pop(0)
                ip = old_lease[0]
                self.leases.append((ip, dev_name, time.time(), []))
    
            pkt = bytearray(
                bytes([int(x) for x in ip.split(".")]) +
                bytes([int(x) for x in self.gateway_ip.split(".")]) +
                bytes([255, 255, 255, 0]) +
                bytes([8, 8, 8, 8]) +
                bytes([8, 8, 4, 4]) +
                dev_name +
                b"\x00"
            )
    
            pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)
    
            return pkt
```

The `get_lease` function appends `dev_name` to the `leases` list, takes the next available `ip` from the `ips` list and uses that to generate a packet. This packet is then encrypted using the result from `get_entropy_from_lavalamps` as a key and a CRC code at the end.

```
    def get_entropy_from_lavalamps(self):
            # Get entropy from all available lava-lamp RNG servers
            # Falling back to local RNG if necessary
            entropy_pool = RNG_INIT
    
            for ip, name, ts, tags in self.leases:
                if b"rngserver" in name:
                    try:
                        # get entropy from the server
                        output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text  
                        entropy_pool += sha256(output.encode())
                    except:
                        # if the server is broken, get randomness from local RNG instead
                        entropy_pool += sha256(secrets.token_bytes(512))
    
            return sha256(entropy_pool)
```

Analyzing the `get_entropy_from_lavalamps` function, we noticed that if the name of the lease does not contain `rngserver`, then the result will always be the same, since `RNG_INIT` is fixed. **This ended up being the source of the vulnerability**.

### FlagServer

This server is very similar to the DHCP Server.

```
    def __init__(self, dhcp):
            self.mac = bytes.fromhex("53 79 82 b5 97 eb")
            self.dns = dns.resolver.Resolver()
            self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))
```

The flag is used when `msg` starts with `\x03`.

```
        def send_flag(self):
            with open("flag.txt", "r") as f:
                flag = f.read().strip()
            curl("example.com", f"/{flag}", self.dns)
    
        def process_pkt(self, pkt):
            assert pkt is not None
    
            src_mac = pkt[:6]
            dst_mac = pkt[6:12]
            msg = pkt[12:]
    
            if dst_mac != self.mac:
                return None
    
            if src_mac == self.mac:
                return None
    
            if len(msg) and msg.startswith(b"\x02"):
                # lease response
                pkt = msg[1:-4]
                pkt = decrypt_msg(pkt)
                crc = msg[-4:]
                assert crc == calc_crc(pkt)
    
                self.ip = ".".join(str(x) for x in pkt[0:4])
                self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
                self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
                self.dns1 = ".".join(str(x) for x in pkt[12:16])
                self.dns2 = ".".join(str(x) for x in pkt[16:20])
                self.dns.nameservers = [self.dns1, self.dns2]
                assert pkt.endswith(b"\x00")
    
                print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)
    
                return None
    
            elif len(msg) and msg.startswith(b"\x03"):
                # FREE FLAGES!!!!!!!
                self.send_flag()
                return None
    
            else:
                return None
```

The flag is sent to `http://example.com/<flag>` and the domain `example.com` is resolved using the `dns` object. We must then gain control of the nameserver of `dns`, so that `example.com` resolves to a URL controlled by us, sending us the flag.

In order to change the `dns.nameservers` value, we must send a message that starts with `\x02`. However, we cannot send our message directly, since it needs to be encrypted using `ChaCha20-Poly1305` with a key we do not know.

## Solution

The server uses `ChaCha20-Poly1305`. We noticed that the nonce is equal to `sha256(msg[:32] + nonce[:32])[:12]`. However, since we control the value of `msg`, and the `nonce` is the result of `get_entropy_from_lavalamps` which as we have seen before can always be the same, this implies that we can ensure that the nonce used in `ChaCha20-Poly1305` is always the same and perform a reused-nonce attack.

We just need to find a way of generating a valid tag for the encrypted message we want to send to `FlagServer`.

`Poly1305` works by creating a polynomial over \\(\mathbb{F}_p\\), with prime \\(p = 2^{130} - 5\\).

\\[P(x) = \sum_{n=1}^{q} c_ix^{q-i} \pmod p\\] 

where the \\(c_i\\)’s are the bytes of the message to be authenticated in 16-byte blocks.

The tag is then generated as

\\[tag = (P(r) + s) \pmod{2^{128}}\\] 

where \\(r,s\\) are the secret key values.

However, in our case, we can encrypt with constant key and nonce, therefore

\\[t = (\sum_{n=1}^{q} c_ir^{q-i} \pmod p + s) \pmod{2^{128}}\\] \\[t' = (\sum_{n=1}^{q} c_i'r^{q-i} \pmod p + s) \pmod{2^{128}}\\] 

To get rid of \\(\pmod {2^{128}}\\)

\\[t = (\sum_{n=1}^{q} c_ir^{q-i} \pmod p + s) + k_1 \cdot 2^{128}\\] \\[t' = (\sum_{n=1}^{q} c_i'r^{q-i} \pmod p + s) + k_2 \cdot 2^{128}\\] 

with \\(0 \leq k1,k2 \leq 5\\). The possible values for each \\(k_i\\) are small due to the fact that \\(3\cdot 2^{128} \leq p \leq 4\cdot 2^{128}\\). In order to eliminate \\(s\\),

\\[t - t' = \sum_{n=1}^{q} (c_i - c_i')r^{q-i} \pmod p + (k_1 - k_2) \cdot 2^{128}\\] 

Therefore we can test the possible \\(k_1, k_2\\) values and solve the equation above for \\(r\\). By looking at the source code of the `ChaCha20-Poly1305` libraries, we also added one extra test for `r`: `r & 0x0ffffffc0ffffffc0ffffffc0fffffff == r`, as `r` is clamped before being used.

Once we know \\(r\\), we know \\(s\\), since

\\[s = tag - P(r) \pmod{2^{128}}\\] 

Having this, we can then forge a valid tag for any message of our choice and therefore change the `dns.nameservers` variable and get the flag.

## Conclusion

Finally, after being able to change the `dns.nameservers` variable, we get the flag. The solution script can be found [here](https://sectt.github.io/writeups/Plaid24/DHCPPP/exploit.py).

**Flag:`PCTF{d0nt_r3u5e_th3_n0nc3_d4839ed727736624}`**
