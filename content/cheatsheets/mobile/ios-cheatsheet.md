---
title: "iOS CTF Cheatsheet - libimobiledevice, class-dump, frida-ios-dump, codesign"
category: mobile
subcategory: ios
type: cheatsheet
tags: [ios, ideviceinstaller, libimobiledevice, idevicesyslog, frida-ios-dump, class-dump, plutil, codesign, otool, lipo, ipa, ssh, iproxy, objection, keychain, mach-o, swift-demangle]
summary: "Command reference for iOS app analysis: device tooling, IPA handling, Mach-O inspection, decryption, jailbroken SSH workflow and objection."
tools: [libimobiledevice, ideviceinstaller, class-dump, frida, objection, otool, codesign, plutil]
related: [ios-static-analysis, ios-frida-runtime, mobile-traffic-interception, android-cheatsheet]
---

## Device discovery and info (libimobiledevice)

```bash
idevice_id -l                                    # udids of attached devices
idevice_id -n                                    # devices visible over the network
idevicepair pair                                 # trust the computer (tap Trust on device)
idevicepair validate
ideviceinfo                                      # all device properties
ideviceinfo -k ProductVersion                    # ios version
ideviceinfo -k CPUArchitecture                   # arm64 / arm64e
ideviceinfo -k DeviceName -k UniqueDeviceID
ideviceinfo -q com.apple.mobile.battery          # a specific domain
idevicename                                      # device name
idevicedate                                      # device clock
idevicediagnostics restart | sleep | shutdown
ideviceactivation state
idevicedebug -d run com.ctf.app                  # launch with stdout (dev-signed apps)
```

## Installing and removing apps

```bash
ideviceinstaller -l                              # installed apps
ideviceinstaller -l -o list_user                 # user apps only
ideviceinstaller -l -o list_system
ideviceinstaller -i app.ipa                      # install
ideviceinstaller -U com.ctf.app                  # uninstall
ideviceinstaller -u <udid> -i app.ipa            # target one device
ios-deploy -c                                    # list devices
ios-deploy -b app.ipa                            # install and run, with output
ios-deploy -b app.ipa -d                         # install and attach lldb
ios-deploy --bundle_id com.ctf.app --uninstall
ipatool download -b com.example.app              # pull an ipa with an apple id (if licensed)
```

## Logs, crashes and app containers

```bash
idevicesyslog                                    # live system log
idevicesyslog | grep -i ctf
idevicesyslog -p com.ctf.app                     # filter by process
idevicecrashreport -e ./crashes                  # pull and delete crash logs
ls ./crashes | grep -i ctf
idevicebackup2 backup --full ./backup            # itunes-style backup
idevicebackup2 unback ./backup                   # expand into a readable tree
idevicebackup2 -i restore ./backup
afcclient ls /                                   # browse the media partition
ifuse /mnt/iphone                                # mount the media partition (needs fuse)
ifuse --documents com.ctf.app /mnt/app           # app Documents if UIFileSharingEnabled
```

## Unpacking and inspecting an IPA

```bash
unzip -l app.ipa | head -40
unzip -q app.ipa -d ipa-out
APP=$(find ipa-out/Payload -maxdepth 1 -name '*.app')
BIN="$APP/$(basename "$APP" .app)"
file "$BIN"
ls -la "$APP"
ls -la "$APP/Frameworks"
plutil -p "$APP/Info.plist"
plutil -convert xml1 -o Info.xml "$APP/Info.plist"
plutil -extract CFBundleIdentifier raw -o - "$APP/Info.plist"
plutil -extract CFBundleURLTypes xml1 -o - "$APP/Info.plist"
plutil -p "$APP/Info.plist" | grep -i UsageDescription
plutil -p "$APP/Info.plist" | grep -A5 NSAppTransportSecurity
security cms -D -i "$APP/embedded.mobileprovision" > profile.plist
plutil -p profile.plist | head -60
assetutil --info "$APP/Assets.car" | head -40
find "$APP" -name '*.plist' -exec sh -c 'echo "== $1"; plutil -p "$1"' _ {} \;
find "$APP" -name '*.db' -o -name '*.sqlite' -o -name '*.json' -o -name '*.js'
```

## Mach-O inspection

```bash
lipo -info "$BIN"                                 # which architecture slices exist
lipo -thin arm64 "$BIN" -output bin.arm64         # extract one slice
lipo -detailed_info "$BIN"
otool -h bin.arm64                                # header
otool -l bin.arm64 | grep -E 'cmd LC_|name |path '
otool -l bin.arm64 | grep -A6 LC_ENCRYPTION_INFO  # cryptid 1 = fairplay encrypted
otool -L bin.arm64                                # linked dylibs / third-party sdks
otool -o bin.arm64 | head -60                     # objective-c metadata
otool -v -s __TEXT __cstring bin.arm64 | head -60
otool -v -s __TEXT __objc_methname bin.arm64 | head -60
otool -v -s __DATA __objc_classlist bin.arm64 | head
otool -tV bin.arm64 | head -60                    # disassembly
nm -gU bin.arm64 | head -40                       # exported symbols
nm -gU bin.arm64 | grep '\$s' | head -40          # swift mangled symbols
swift demangle '$s3Foo14ViewControllerC5checkySbSSF'
strings -a -n 6 bin.arm64 > strings.txt
grep -oE 'https?://[^"[:space:]]+' strings.txt | sort -u
grep -iE 'api[_-]?key|token|secret|password' strings.txt | head -40
```

## Class metadata

```bash
class-dump -H -o headers/ bin.arm64               # objective-c headers
class-dump --list-arches app.ipa
class-dump -a -A bin.arm64 | head -80             # with ivar/method addresses
grep -rn -iE 'flag|secret|verify|check|decrypt|jailbr|pin' headers/ | head -40
grep -rn '@interface' headers/ | head -40
dsdump --objc --color bin.arm64 | head -60        # alternative to class-dump
dsdump --swift bin.arm64 | head -60
```

## Code signing and entitlements

```bash
codesign -dv --verbose=4 "$APP"
codesign -d --entitlements :- "$APP"
codesign -d --entitlements :- "$APP" | grep -A5 keychain-access-groups
codesign -d -r- "$APP"                            # designated requirement
codesign --verify --deep --strict --verbose=2 "$APP"
security find-identity -v -p codesigning          # available signing identities
codesign -f -s "Apple Development: you (TEAMID)" --entitlements ent.plist "$APP"
zip -qry resigned.ipa Payload/
xcrun -sdk iphoneos PackageApplication -v "$APP" -o resigned.ipa 2>/dev/null || true
```

## Decrypting a FairPlay binary (jailbroken)

```bash
iproxy 2222 22 &                                  # ssh over usb
iproxy 27042 27042 &                              # frida over usb
python3 dump.py -H 127.0.0.1 -p 2222 -u root -P alpine com.ctf.app   # frida-ios-dump
bagbak com.ctf.app                                # alternative dumper
ssh -p 2222 root@127.0.0.1 "flexdecrypt /var/containers/Bundle/Application/*/Foo.app/Foo"
otool -l Foo.decrypted | grep -A4 LC_ENCRYPTION_INFO   # cryptid must now be 0
```

## Jailbroken device SSH workflow

```bash
iproxy 2222 22 &
ssh -p 2222 root@127.0.0.1                        # legacy default password: alpine
# change it immediately: passwd
scp -P 2222 root@127.0.0.1:/var/mobile/Documents/db.sqlite .
scp -P 2222 ./tool root@127.0.0.1:/usr/local/bin/

# on the device:
#   find the app bundle and its data container
ssh -p 2222 root@127.0.0.1 "ls /var/containers/Bundle/Application/"
ssh -p 2222 root@127.0.0.1 "ls /var/mobile/Containers/Data/Application/"
ssh -p 2222 root@127.0.0.1 "find /var -name 'Foo.app' -maxdepth 5 2>/dev/null"
ssh -p 2222 root@127.0.0.1 "ps aux | grep -i ctf"
ssh -p 2222 root@127.0.0.1 "cycript -p Foo"       # legacy live exploration
ssh -p 2222 root@127.0.0.1 "ldid -e /path/Foo"    # entitlements on-device
ssh -p 2222 root@127.0.0.1 "sqlite3 /var/mobile/Library/Keychains/keychain-2.db .tables"
ssh -p 2222 root@127.0.0.1 "security dump-trust-settings -d"
ssh -p 2222 root@127.0.0.1 "tcpdump -i any -s 0 -w /tmp/cap.pcap"
ssh -p 2222 root@127.0.0.1 "uicache --all"        # refresh the springboard after installing
```

## Frida and objection on iOS

```bash
frida-ps -U                                       # processes
frida-ps -Ua                                      # running apps with bundle ids
frida-ps -Uai                                     # all installed apps
frida -U -f com.ctf.app -l hook.js --no-pause     # spawn
frida -U -n MyApp -l hook.js                      # attach
frida-trace -U -f com.ctf.app -m '-[NSURLSession *]'
frida-trace -U -n MyApp -m '*[* *Password*]'
frida-trace -U -n MyApp -i 'SecItemCopyMatching'
objection --gadget com.ctf.app explore
objection patchipa --source app.ipa --codesign-signature TEAMID
# inside the objection shell:
#   env
#   ios bundles list_bundles
#   ios plist cat Info.plist
#   ios nsuserdefaults get
#   ios keychain dump
#   ios keychain dump --json keychain.json
#   ios cookies get
#   ios sslpinning disable
#   ios jailbreak disable
#   ios hooking list classes
#   ios hooking search methods password
#   ios hooking watch class CTFLoginViewController
#   ios hooking watch method "-[CTFLoginViewController checkPassword:]" --dump-args --dump-return
#   ios pasteboard monitor
#   memory list modules
#   memory search --string "flag{" --offsets-only
#   file download Documents/db.sqlite
#   file upload ./payload.json Documents/payload.json
```

## Simulator (no device needed)

```bash
xcrun simctl list devices
xcrun simctl boot "iPhone 15"
xcrun simctl install booted Foo.app
xcrun simctl launch --console booted com.ctf.app
xcrun simctl launch booted com.ctf.app -deeplink "ctfapp://open"
xcrun simctl openurl booted "ctfapp://open/flag"
xcrun simctl get_app_container booted com.ctf.app data
xcrun simctl spawn booted log stream --predicate 'process == "Foo"'
xcrun simctl io booted screenshot shot.png
xcrun simctl terminate booted com.ctf.app
xcrun simctl erase booted
# simulator binaries are x86_64/arm64 and NEVER fairplay encrypted - easiest static target
```

## Traffic interception

```bash
# 1. route: Settings > Wi-Fi > (i) > Configure Proxy > Manual > host:8080
# 2. install the CA: open http://<proxy-ip>:8080 in Safari, install the profile
# 3. TRUST it: Settings > General > About > Certificate Trust Settings > enable
mitmproxy --listen-host 0.0.0.0 --listen-port 8080
mitmproxy --mode wireguard                        # whole device, no proxy setting needed
rvictl -s "$(idevice_id -l | head -1)"            # macOS: virtual mirror interface
tcpdump -i rvi0 -s 0 -w ios.pcap
rvictl -x "$(idevice_id -l | head -1)"
tshark -r ios.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u
ssh -p 2222 root@127.0.0.1 "security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/burp.pem"
```

## Useful on-device paths

```bash
# app bundle (read-only, signed)
#   /var/containers/Bundle/Application/<UUID>/Foo.app/
# app data container
#   /var/mobile/Containers/Data/Application/<UUID>/
#     Documents/           user files, often the flag
#     Library/Preferences/<bundleid>.plist    NSUserDefaults
#     Library/Caches/                         URL cache, images
#     Library/Cookies/Cookies.binarycookies
#     tmp/
# shared app group container
#   /var/mobile/Containers/Shared/AppGroup/<UUID>/
# keychain database
#   /private/var/Keychains/keychain-2.db
# installed app metadata
#   /var/mobile/Library/Caches/com.apple.mobile.installation.plist
plutil -p Library/Preferences/com.ctf.app.plist
python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb')))" Info.plist
```
