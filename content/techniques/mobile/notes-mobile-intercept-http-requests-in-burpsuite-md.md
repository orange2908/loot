---
title: "Intercept HTTP Requests in Burpsuite (Mobile)"
category: "mobile"
subcategory: "runtime"
type: "technique"
tags: ["my-notes", "personal", "burp", "frida", "ssl-pinning", "adb", "mobile"]
summary: "Personal note: Intercept HTTP Requests in Burpsuite (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/Intercept HTTP Requests in Burpsuite.md"
---

## Prepare the certificate

- Get the burp certificate 
```bash
curl localhost:8080/cert -o cert.deb
```

- Convert the certificate to PEM format
```bash
openssl x509 -inform der -in cert.deb -out burp.pem
```

- Rename the file to the MD5 sum of the subject
```bash
openssl x509 -inform pem -subject_hash_old -in burp.pem
```
- name : `9a5ba575.0`
- push the certificate to the device
```bash
adb push 9a5ba575.0 /system/etc/security/cacerts/
```
---
## Push the certificate to the android device

- Changing the file system to RW so we can write to it (initially it is Read only)
```
~/Tools/mobile/cert ❯ adb shell                                    
vbox86p:/ # su 
:/ # mount -o remount,rw /
:/ # exit
vbox86p:/ # exit
```

```bash
mount -o rw,remount /system
```

- push the certificate to the android device
```bash
adb push 9a5ba575.0 /system/etc/security/cacerts/
```
---
## Proxy Configuration
### set device proxy
```bash
adb shell settings put global http_proxy 192.168.118.140:8080
```
### unset device proxy
```bash
adb shell settings put global http_proxy :0
```
### aliases set/unset
- add to `~/.zshrc`
```bash
alias adb_set_proxy="adb shell settings put global http_proxy $(ip -o -4 addr show eth0 | awk '{print $4}' | sed 's/\/.*//g'):8080"

alias adb_unset_proxy="adb shell settings put global http_proxy :0"
```
---
# SSL Pinning Bypass using Frida

## Installing Frida

- Installing Frida on the local machine
```bash
pip install frida-tools
```

- Download frida-server from github releases
```bash
wget https://github.com/frida/frida/releases/download/16.1.1/frida-server-16.1.1-android-x86_64.xz
```

- Unzip it
```bash
unxz frida-server-16.1.1-android-x86_64.xz
```

- Rename it frida-server
```bash
mv frida-server-16.1.1-android-x86_64.xz frida-server
```

- Push it to the android device
```bash
adb push frida-server /data/local/tmp/
```

- Make it executable
```bash
adb shell "chmod 755 /data/local/tmp/frida-server"
```

- Run it
```bash
adb shell "/data/local/tmp/frida-server &"
```

# SSL Pinning Bypass [Instagram Example]

- Download the instagram ssl pinning bypass script
```bash
https://github.com/Eltion/Instagram-SSL-Pinning-Bypass
```

```bash
https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/blob/main/instagram-ssl-pinning-bypass.js
```

- Run it
```bash
frida -U -l ./instagram-ssl-pinning-bypass.js -f com.instagram.android
```

---

*From your own notes: `Mobile/Intercept HTTP Requests in Burpsuite.md`*
