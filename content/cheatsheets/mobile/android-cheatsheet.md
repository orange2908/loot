---
title: "Android CTF Cheatsheet - adb, apktool, jadx, am, pm, content"
category: mobile
subcategory: android
type: cheatsheet
tags: [adb, apktool, jadx, apksigner, zipalign, aapt2, dex2jar, keytool, logcat, emulator, avd, drozer, frida, objection, am, pm, content, dumpsys, smali]
summary: "Dense command reference for Android reversing and app attack: adb, build tools, decompilers, emulator setup, am/pm/content and logcat."
tools: [adb, apktool, jadx, apksigner, zipalign, aapt2, emulator, drozer, frida]
related: [android-apk-triage, android-smali-patching, android-exported-components, adb-objection-recipes]
---

## Device connection

```bash
adb devices -l                               # list devices with model/product
adb start-server && adb kill-server          # restart when a device goes "offline"
adb -s emulator-5554 shell                   # target one device when several are attached
adb connect 192.168.1.50:5555                # adb over wifi (after: adb tcpip 5555)
adb tcpip 5555                               # switch a usb device to tcp mode
adb usb                                      # switch back to usb
adb root                                     # restart adbd as root (userdebug/emulator only)
adb unroot
adb remount                                  # make /system writable (needs adb root + verity off)
adb disable-verity && adb reboot             # required before remount on many builds
adb wait-for-device
adb reboot / adb reboot bootloader / adb reboot recovery
adb shell getprop ro.build.version.release   # android version
adb shell getprop ro.build.version.sdk       # api level
adb shell getprop ro.product.cpu.abi         # arm64-v8a / armeabi-v7a / x86_64
adb shell getprop | grep -i debug            # ro.debuggable, ro.secure
adb shell whoami && adb shell id
```

## Package management (pm)

```bash
adb install app.apk                          # install
adb install -r app.apk                       # reinstall keeping data
adb install -d app.apk                       # allow version downgrade
adb install -g app.apk                       # grant all runtime permissions
adb install -t app.apk                       # allow test-only apks
adb install-multiple base.apk split_*.apk    # split apks / app bundles
adb uninstall com.ctf.app
adb uninstall -k com.ctf.app                 # keep data and cache
adb shell pm list packages                   # all packages
adb shell pm list packages -3                # third-party only
adb shell pm list packages -f com.ctf        # with the apk path
adb shell pm list packages -e                # enabled only
adb shell pm path com.ctf.app                # where the apk lives (incl. splits)
adb shell pm dump com.ctf.app | head -80     # everything the framework knows
adb shell pm clear com.ctf.app               # wipe app data
adb shell pm disable-user com.ctf.app
adb shell pm enable com.ctf.app
adb shell pm grant com.ctf.app android.permission.READ_EXTERNAL_STORAGE
adb shell pm revoke com.ctf.app android.permission.CAMERA
adb shell pm list permissions -d -g          # dangerous permissions by group
adb shell pm get-app-links com.ctf.app       # app-link verification state
adb shell pm query-activities -a android.intent.action.VIEW -d "ctfapp://x"
adb shell cmd package resolve-activity --brief com.ctf.app
```

## Pulling an APK off a device

```bash
adb shell pm path com.ctf.app                       # -> package:/data/app/.../base.apk
adb pull /data/app/~~abc==/com.ctf.app-1/base.apk .
for p in $(adb shell pm path com.ctf.app | sed 's/package://' | tr -d '\r'); do adb pull "$p"; done
adb shell pm list packages -f | grep ctf            # find the path in one go
adb backup -f app.ab -noapk com.ctf.app             # legacy data backup
adb shell bmgr backupnow com.ctf.app
```

## Static analysis

```bash
file app.apk && unzip -l app.apk | head -40         # it is a zip
unzip -q -o app.apk -d out-zip                      # raw view: assets, lib, META-INF
apktool d -f -o out-apktool app.apk                 # smali + decoded resources
apktool d -r -f -o out-nores app.apk                # skip resources (faster, never fails)
apktool d -s -f -o out-nosmali app.apk              # skip smali, resources only
apktool b out-apktool -o unsigned.apk --use-aapt2   # rebuild
apktool if framework-res.apk                        # install an OEM framework
jadx -d out-jadx app.apk                            # dex -> java
jadx -d out-jadx --deobf --show-bad-code app.apk    # rename a/a/a, keep broken methods
jadx -d out-jadx -r app.apk                         # skip resources
jadx-gui app.apk                                    # interactive, with rename persistence
aapt2 dump badging app.apk                          # package, versions, permissions, launcher
aapt2 dump xmltree --file AndroidManifest.xml app.apk
aapt2 dump resources app.apk | head -60
d2j-dex2jar.sh classes.dex -o classes.jar           # dex -> jar for jd-gui/procyon
unzip -p app.apk classes.dex > classes.dex
baksmali d classes.dex -o smali-out                 # low-level smali
smali a smali-out -o classes-new.dex
apkleaks -f app.apk -o apkleaks.txt                 # regex secret scan
strings -n 8 -a out-zip/classes.dex | sort -u | head -50
```

## Grep targets

```bash
grep -rIn -E 'flag\{|CTF\{' out-jadx/ out-apktool/
grep -rIn -iE 'api[_-]?key|secret|token|password|bearer' out-jadx/sources | head -60
grep -rIoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' out-jadx/ | sort -u
grep -rIn 'AIza[0-9A-Za-z_-]\{35\}' out-apktool/
grep -rIn -E 'Cipher\.getInstance|SecretKeySpec|MessageDigest|Base64\.decode' out-jadx/sources
grep -rIn -E 'System\.loadLibrary|native ' out-jadx/sources
grep -rIn -E 'addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess' out-jadx/sources
grep -rIn -E 'CertificatePinner|checkServerTrusted|TrustManager' out-jadx/sources
grep -nE 'android:exported|android:debuggable|allowBackup|usesCleartextTraffic' out-apktool/AndroidManifest.xml
cat out-apktool/res/xml/network_security_config.xml
cat out-apktool/res/values/strings.xml
find out-apktool -name 'BuildConfig.smali' -exec grep -H 'const-string' {} +
```

## Signing and rebuilding

```bash
keytool -genkeypair -v -keystore debug.keystore -alias androiddebugkey \
  -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android \
  -dname "CN=Android Debug,O=Android,C=US"
zipalign -p -f 4 unsigned.apk aligned.apk          # align BEFORE signing
zipalign -c -v 4 aligned.apk                       # verify alignment
apksigner sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --out signed.apk aligned.apk
apksigner verify --verbose --print-certs signed.apk
jarsigner -keystore debug.keystore -storepass android signed.apk androiddebugkey  # v1 only
keytool -printcert -jarfile app.apk                # signer cert without installing
unzip -p app.apk META-INF/CERT.RSA | keytool -printcert
apk-mitm app.apk                                   # auto patch network-security-config + sign
```

## Activities, services, receivers (am)

```bash
adb shell am start -n com.ctf.app/.MainActivity
adb shell am start -n com.ctf.app/com.ctf.app.SecretActivity
adb shell am start -W -n com.ctf.app/.MainActivity           # wait and print the result
adb shell am start -a android.intent.action.VIEW -d "ctfapp://open/x"
adb shell am start -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE -d "https://app.ctf.example/l/1"
adb shell am start -n com.ctf.app/.A --es key value          # string extra
adb shell am start -n com.ctf.app/.A --ei n 42               # int
adb shell am start -n com.ctf.app/.A --el big 4294967296     # long
adb shell am start -n com.ctf.app/.A --ez flag true          # boolean
adb shell am start -n com.ctf.app/.A --ef r 1.5              # float
adb shell am start -n com.ctf.app/.A --esa list a,b,c        # string array
adb shell am start -n com.ctf.app/.A --eu uri "content://x"  # uri
adb shell am start -n com.ctf.app/.A -t application/json -d "file:///sdcard/p.json"
adb shell am start -n com.ctf.app/.A --grant-read-uri-permission
adb shell am start-foreground-service -n com.ctf.app/.FlagService --es cmd dump
adb shell am startservice -n com.ctf.app/.FlagService        # api < 26
adb shell am stopservice -n com.ctf.app/.FlagService
adb shell am broadcast -a com.ctf.app.RUN --es cmd reveal
adb shell am broadcast -n com.ctf.app/.CmdReceiver -a com.ctf.app.RUN
adb shell am force-stop com.ctf.app
adb shell am kill com.ctf.app
adb shell am set-debug-app -w com.ctf.app                    # wait for a debugger
adb shell am clear-debug-app
adb shell am monitor                                          # watch crashes/ANRs
adb shell am instrument -w com.ctf.app.test/androidx.test.runner.AndroidJUnitRunner
```

## Content providers (content)

```bash
adb shell content query --uri content://com.ctf.app.notes/notes
adb shell content query --uri content://com.ctf.app.notes/notes --projection title:body
adb shell content query --uri content://com.ctf.app.notes/notes --where "id=1" --sort "id DESC"
adb shell content insert --uri content://com.ctf.app.notes/notes --bind title:s:pwn
adb shell content update --uri content://com.ctf.app.notes/notes --bind body:s:x --where "id=1"
adb shell content delete --uri content://com.ctf.app.notes/notes --where "id=1"
adb shell content read --uri "content://com.ctf.app.files/f/../databases/app.db" > app.db
adb shell content call --uri content://com.ctf.app.notes --method getFlag --arg x
adb shell content query --uri content://com.ctf.app.notes/notes \
  --where "1=1) UNION SELECT name,sql FROM sqlite_master --"
adb shell content query --uri content://settings/secure
adb shell content query --uri content://com.android.contacts/data
```

## Files and app data

```bash
adb shell ls -la /data/data/com.ctf.app                    # needs root
adb shell run-as com.ctf.app ls -la /data/data/com.ctf.app # needs android:debuggable
adb exec-out run-as com.ctf.app cat databases/app.db > app.db
adb exec-out run-as com.ctf.app tar -cf - . > appdata.tar
adb exec-out "tar -C /data/data -cf - com.ctf.app" > appdata.tar      # with root
adb pull /data/data/com.ctf.app/shared_prefs ./shared_prefs
adb push payload.json /sdcard/
adb shell ls -laR /sdcard/Android/data/com.ctf.app
adb shell du -sh /data/data/com.ctf.app/*
sqlite3 app.db "PRAGMA wal_checkpoint(TRUNCATE);" ".tables" ".schema"
sqlite3 app.db ".dump" > dump.sql
strings -n 6 app.db app.db-wal | grep -iE 'flag|token'
adb shell cmd package compile -m speed -f com.ctf.app       # force AOT compile
```

## Logcat

```bash
adb logcat -c                                       # clear the buffer
adb logcat -d > log.txt                             # dump and exit
adb logcat -v time                                  # with timestamps
adb logcat -v threadtime --pid=$(adb shell pidof -s com.ctf.app)
adb logcat *:E                                      # errors only
adb logcat CTF:D *:S                                # only tag "CTF" at debug
adb logcat -b crash -d                              # crash buffer
adb logcat -b all -d                                # main+system+crash+events
adb logcat | grep -iE 'flag|token|exception'
adb logcat -s AndroidRuntime                        # java crashes
adb logcat --regex 'flag\{'
adb shell dmesg | tail -40                          # kernel log (needs root)
adb bugreport bug.zip                               # everything, for offline grep
```

## dumpsys and system state

```bash
adb shell dumpsys package com.ctf.app | head -120
adb shell dumpsys package com.ctf.app | sed -n '/Activity Resolver Table/,/^$/p'
adb shell dumpsys activity activities | grep -A5 com.ctf.app
adb shell dumpsys activity top | head -60
adb shell dumpsys activity services com.ctf.app
adb shell dumpsys activity broadcasts | grep -i ctf
adb shell dumpsys activity providers | grep -A6 com.ctf.app
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
adb shell dumpsys meminfo com.ctf.app
adb shell dumpsys batterystats --charged com.ctf.app | head -40
adb shell dumpsys netstats | head -40
adb shell settings list global | grep -i proxy
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings put global http_proxy :0
adb shell pidof com.ctf.app
adb shell ps -A | grep ctf
adb shell top -n 1 | head -20
adb shell netstat -tulpn 2>/dev/null | head -20
adb shell cat /proc/$(adb shell pidof -s com.ctf.app)/maps | head -40
```

## Emulator and AVD

```bash
sdkmanager --list | head -40
sdkmanager "system-images;android-30;google_apis;x86_64" "platform-tools" "build-tools;34.0.0"
avdmanager create avd -n ctf30 -k "system-images;android-30;google_apis;x86_64" -d pixel
avdmanager list avd
emulator -list-avds
emulator -avd ctf30 -writable-system -no-snapshot-load        # writable /system for CA install
emulator -avd ctf30 -http-proxy http://192.168.1.10:8080
emulator -avd ctf30 -netdelay none -netspeed full -gpu swiftshader_indirect
emulator -avd ctf30 -wipe-data                                # factory reset
adb emu kill                                                  # shut the emulator down
adb shell settings put global window_animation_scale 0        # speed up the UI
adb shell input text "flagcandidate"
adb shell input keyevent 66                                   # KEYCODE_ENTER
adb shell input tap 540 1200
adb shell input swipe 540 1600 540 600
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png
adb shell screenrecord --time-limit 20 /sdcard/v.mp4
adb shell monkey -p com.ctf.app -v 500                        # random UI fuzzing
```

## Frida and objection

```bash
frida --version && adb shell /data/local/tmp/frida-server --version
adb push frida-server-16.0.0-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && su -c '/data/local/tmp/frida-server -D'"
frida-ps -U ; frida-ps -Ua ; frida-ps -Uai
frida -U -f com.ctf.app -l hook.js --no-pause
frida -U -n com.ctf.app -l hook.js
frida-trace -U -f com.ctf.app -j 'com.ctf.app.*!*'
frida-trace -U -n com.ctf.app -i 'strcmp' -i 'open'
objection -g com.ctf.app explore
objection -g com.ctf.app explore -s "android sslpinning disable"
objection -g com.ctf.app explore -s "android root disable"
objection patchapk -s app.apk                                  # embed frida-gadget
frida-dexdump -U -f com.ctf.app -o ./dexout
jnitrace -l libnative-lib.so -m spawn com.ctf.app
```

## drozer

```bash
adb install drozer-agent.apk
adb forward tcp:31415 tcp:31415
adb shell am start -n com.mwr.dz/.activities.MainActivity     # enable the embedded server
drozer console connect
# run app.package.list -f ctf
# run app.package.attacksurface com.ctf.app
# run app.activity.info -a com.ctf.app
# run app.activity.start --component com.ctf.app com.ctf.app.SecretActivity
# run app.service.info -a com.ctf.app
# run app.broadcast.send --action com.ctf.app.RUN --extra string cmd reveal
# run app.provider.info -a com.ctf.app
# run app.provider.finduri com.ctf.app
# run app.provider.query content://com.ctf.app.notes/notes --vertical
# run scanner.provider.injection -a com.ctf.app
# run scanner.provider.traversal -a com.ctf.app
# run scanner.misc.native -a com.ctf.app
```

## Native libraries

```bash
file out-zip/lib/*/*.so
readelf -h out-zip/lib/arm64-v8a/libnative-lib.so
readelf -d out-zip/lib/arm64-v8a/libnative-lib.so | head -20
nm -D --defined-only out-zip/lib/arm64-v8a/libnative-lib.so | grep -E 'Java_|JNI_OnLoad'
nm -D --undefined-only out-zip/lib/arm64-v8a/libnative-lib.so | grep -iE 'ptrace|dlopen|AES'
objdump -d --section=.text out-zip/lib/arm64-v8a/libnative-lib.so | head -60
strings -n 8 out-zip/lib/arm64-v8a/libnative-lib.so | sort -u > native-strings.txt
readelf -x .init_array out-zip/lib/arm64-v8a/libnative-lib.so
analyzeHeadless /tmp/proj ctf -import out-zip/lib/arm64-v8a/libnative-lib.so
```

## Certificates and proxying

```bash
openssl x509 -inform DER -in cacert.der -out burp.pem
openssl x509 -inform PEM -subject_hash_old -in burp.pem -noout     # android system store name
cp burp.pem 9a5ba575.0 && openssl x509 -inform PEM -in burp.pem -text -noout >> 9a5ba575.0
adb push 9a5ba575.0 /sdcard/
adb root && adb remount && adb push 9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0 && adb reboot
adb reverse tcp:8080 tcp:8080                       # proxy over usb
adb shell settings put global http_proxy 127.0.0.1:8080
mitmproxy --listen-host 0.0.0.0 --listen-port 8080
mitmproxy --mode transparent --showhost
adb shell su -c 'tcpdump -i any -s 0 -w /sdcard/cap.pcap'
adb shell su -c 'tcpdump -i any -s 0 -w -' | wireshark -k -i -
```
