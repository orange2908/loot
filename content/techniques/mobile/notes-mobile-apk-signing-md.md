---
title: "APK Signing (Mobile)"
category: "mobile"
subcategory: "rsa"
type: "technique"
tags: ["my-notes", "personal", "rsa", "apktool", "adb", "mobile"]
summary: "-> https://gist.github.com/PuKoren/d0ec0c98350c0e92f467"
source:
  name: "Personal notes"
origin_path: "Mobile/APK Signing.md"
---

### Rebuild an apk from folder
```bash
apktool b <folder>
```
### generate a key to sign an apk
```bash
keytool -genkey -v -keystore key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias HTB-APKrypt
```
### sign the key
```bash
jarsigner -keystore key.jks APKrypt-patched.apk HTB-APKrypt 
```


---

```
- apktool d app-release.apk
- apktool b app-release -o patchedFast.apk
- zipalign -v -p 4 patchedFast.apk patchedFastAligned.apk
- keytool -genkey -v -keystore my-release-key.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000
- apksigner sign --ks my-release-key.keystore --out patchedFastAlignedSigned.apk patchedFastAligned.apk
- adb install -r patchedFastAlignedSigned.apk
```

## Recompile APK 
-> https://gist.github.com/PuKoren/d0ec0c98350c0e92f467
-> https://ctf.zeyu2001.com/2022/nahamcon-ctf-2022/click-me

---

*From your own notes: `Mobile/APK Signing.md`*
