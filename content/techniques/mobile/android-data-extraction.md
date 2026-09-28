---
title: "Android App Data - shared_prefs, SQLite, Keystore and Extraction Without Root"
category: mobile
subcategory: storage
type: technique
tags: [shared-preferences, sqlite, keystore, encryptedsharedpreferences, adb-backup, run-as, allowbackup, debuggable, bmgr, data-extraction, frida, objection, wal, realm, android, storage]
difficulty: medium
summary: "Find where an app keeps its data, and get it off the device with root, with run-as, with adb backup, or by asking the app itself via Frida."
when_to_use:
  - "The flag or a token is stored locally by the app"
  - "You have a device but no root and need /data/data contents"
  - "The app uses EncryptedSharedPreferences or the Android Keystore"
tools: [adb, frida, objection, sqlite3, python]
related: [android-frida-basics, android-exported-components, android-apk-triage, android-root-detection-bypass]
---

## TL;DR

App data lives in `/data/data/<pkg>/` (internal, private) and
`/sdcard/Android/data/<pkg>/` (external, world-ish readable on old versions).
Without root you have four doors: `run-as` (needs `android:debuggable`),
`adb backup` (needs `android:allowBackup` and an old-enough device), an exported
provider, or Frida (the app reads it for you). Keystore keys are non-exportable - so
never try to extract the key, hook the decryption instead.

## Recognise it

- `getSharedPreferences("prefs", MODE_PRIVATE)`, `PreferenceManager.getDefaultSharedPreferences`.
- `SQLiteOpenHelper`, `Room`, `Realm`, `openOrCreateDatabase`.
- `EncryptedSharedPreferences.create(...)` with `MasterKey`/`MasterKeys` (androidx.security).
- `KeyStore.getInstance("AndroidKeyStore")`, `KeyGenParameterSpec`.
- `openFileOutput(...)`, `getFilesDir()`, `getCacheDir()`, `getExternalFilesDir(...)`.
- Manifest `android:allowBackup="true"` or `android:debuggable="true"`.

## Theory

### Layout of `/data/data/<pkg>/`

| Path | Contents |
|---|---|
| `shared_prefs/*.xml` | key/value XML, plaintext unless EncryptedSharedPreferences |
| `databases/*.db` | SQLite; also `-wal` and `-shm` (unflushed data lives in the WAL!) |
| `files/` | `openFileOutput` output, downloaded assets, tokens |
| `cache/`, `code_cache/` | temporary, often contains responses and images |
| `app_webview/` | WebView cookies (`Cookies` SQLite), local storage, cache |
| `no_backup/` | excluded from backup by design (so often where the good stuff is) |
| `lib` | symlink to the extracted native libs |
| `/sdcard/Android/data/<pkg>/` | external files; scoped storage restricts this on API 30+ |

### Encryption realities

- **SharedPreferences** are plain XML. `MODE_PRIVATE` is a filesystem permission, not crypto.
- **EncryptedSharedPreferences** (androidx.security.crypto) encrypts keys with AES-SIV and
  values with AES-GCM, using a master key held in the Android Keystore.
- **Android Keystore** keys with `setUserAuthenticationRequired(false)` and no
  StrongBox can be *used* by the app at any time but never *exported*: `getKey()` returns
  a handle, `getEncoded()` returns null. Therefore the only extraction path is to make the
  app decrypt for you (Frida hook on `Cipher.doFinal`, or call the app's own getter).
- **SQLCipher** databases start with random bytes instead of `SQLite format 3`; the
  passphrase is in the code or derived from a Keystore key -> hook
  `net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase`.

### Backup rules

`android:allowBackup="true"` plus `android:fullBackupContent="@xml/backup_rules"` controls
what `adb backup` and cloud backup include. `adb backup` was removed/neutered on
Android 12+ for most apps, so treat it as a legacy path (still fine on emulators and older
targets). `no_backup/` and `<exclude>` entries never appear in a backup.

## Attack

1. Check the manifest for `debuggable` and `allowBackup` - that decides your route.
2. Rooted / emulator: `adb root` then just `adb pull`.
3. Debuggable: `run-as <pkg>` gives you a shell as the app uid.
4. `allowBackup`: `adb backup -f out.ab <pkg>` then unpack the `.ab`.
5. Neither: Frida - read the files through the app's own `Context`, or hook the decryptor.
6. Always pull `-wal` and `-shm` alongside the `.db`, and run `PRAGMA wal_checkpoint`.

## Code

### With root (or an emulator)

```bash
# emulator / userdebug build: gives adb the root uid
adb root && adb shell whoami        # -> root

# copy the whole app data dir off the device
adb exec-out "tar -C /data/data -cf - com.ctf.app" > appdata.tar
tar xf appdata.tar

# or file by file
adb shell "ls -laR /data/data/com.ctf.app"
adb pull /data/data/com.ctf.app/shared_prefs ./shared_prefs
adb pull /data/data/com.ctf.app/databases ./databases

# external storage (no root needed)
adb shell ls -laR /sdcard/Android/data/com.ctf.app
adb pull /sdcard/Android/data/com.ctf.app ./external
```

### Without root, app is debuggable

```bash
# does run-as work? (needs android:debuggable="true" in the installed apk)
adb shell run-as com.ctf.app id

# browse and read as the app uid
adb shell run-as com.ctf.app ls -la /data/data/com.ctf.app
adb shell run-as com.ctf.app cat /data/data/com.ctf.app/shared_prefs/prefs.xml

# pull a binary file through base64 (run-as cannot be combined with adb pull)
adb shell run-as com.ctf.app cat /data/data/com.ctf.app/databases/app.db |
  base64 -w0 > /dev/null   # sanity check the path first
adb exec-out run-as com.ctf.app cat /data/data/com.ctf.app/databases/app.db > app.db
adb exec-out run-as com.ctf.app cat /data/data/com.ctf.app/databases/app.db-wal > app.db-wal

# copy the whole tree in one shot
adb exec-out run-as com.ctf.app tar -cf - . > appdata.tar

# make a non-debuggable app debuggable: patch the manifest and re-sign
#   apktool d app.apk -o w
#   sed -i '' 's/<application /<application android:debuggable="true" /' w/AndroidManifest.xml
#   apktool b w -o u.apk && zipalign -p -f 4 u.apk a.apk && apksigner sign --ks debug.keystore ...
```

### adb backup route

```bash
# take a full backup (confirm on the device screen; leave the password empty)
adb backup -f app.ab -noapk com.ctf.app
adb backup -f full.ab -apk -shared -all          # everything, legacy devices

# the .ab is a 24-byte header + (optionally deflated) tar
# unpack it with the python helper below, or:
dd if=app.ab bs=1 skip=24 | zlib-flate -uncompress > app.tar 2>/dev/null || true
tar tvf app.tar

# force the backup manager to run (useful when adb backup is throttled)
adb shell bmgr enabled
adb shell bmgr list transports
adb shell bmgr backupnow com.ctf.app
```

```python
#!/usr/bin/env python3
"""unab.py - convert an Android `adb backup` .ab file into a .tar.

Format: "ANDROID BACKUP\n<version>\n<compressed 0|1>\n<encryption none|AES-256>\n"
followed by the (optionally zlib-deflated) tar stream. Encrypted backups need the
user password and are not handled here.

Usage: python3 unab.py app.ab app.tar
"""
from __future__ import annotations

import sys
import zlib


def unab(data: bytes) -> bytes:
    lines = data.split(b"\n", 4)
    if len(lines) < 5 or lines[0] != b"ANDROID BACKUP":
        raise ValueError("not an android backup file")
    version = int(lines[1])
    compressed = lines[2] == b"1"
    encryption = lines[3].decode()
    payload = lines[4]
    if encryption != "none":
        raise ValueError(f"encrypted backup ({encryption}); supply the password and decrypt first")
    if compressed:
        payload = zlib.decompress(payload)
    sys.stderr.write(f"[+] version={version} compressed={compressed} -> {len(payload)} bytes\n")
    return payload


def make_ab(tar_bytes: bytes, compressed: bool = True) -> bytes:
    header = b"ANDROID BACKUP\n5\n" + (b"1" if compressed else b"0") + b"\nnone\n"
    body = zlib.compress(tar_bytes) if compressed else tar_bytes
    return header + body


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    with open(argv[1], "rb") as fh:
        data = fh.read()
    with open(argv[2], "wb") as fh:
        fh.write(unab(data))
    print(f"wrote {argv[2]}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("apps/com.ctf.app/sp/prefs.xml")
            payload = b"<map><string name=\"token\">flag{stored}</string></map>"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        ab = make_ab(buf.getvalue())
        out = unab(ab)
        with tarfile.open(fileobj=io.BytesIO(out)) as tf:
            names = tf.getnames()
        assert names == ["apps/com.ctf.app/sp/prefs.xml"], names
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Reading what you pulled

```bash
# shared prefs are plain xml
for f in shared_prefs/*.xml; do echo "== $f"; cat "$f"; done

# sqlite: always checkpoint the WAL first or you will miss recent rows
sqlite3 app.db "PRAGMA journal_mode;"
sqlite3 app.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 app.db ".tables"
sqlite3 app.db ".schema"
sqlite3 app.db "SELECT * FROM sqlite_master;"
sqlite3 app.db ".dump" > dump.sql

# deleted rows / freelist pages often still hold the flag
strings -n 6 app.db | grep -iE 'flag|token|password' | sort -u
strings -n 6 app.db-wal | grep -iE 'flag|token' | sort -u

# webview cookies
sqlite3 app_webview/Cookies "SELECT host_key, name, value FROM cookies;"

# is it sqlcipher? (no 'SQLite format 3' magic)
head -c 16 app.db | xxd
```

### Frida: make the app hand you its own data

```js
// dump-storage.js - dump shared_prefs, files and decrypted values from inside the app
// run: frida -U -n com.ctf.app -l dump-storage.js
'use strict';

Java.perform(function () {
  var ActivityThread = Java.use('android.app.ActivityThread');
  var ctx = ActivityThread.currentApplication().getApplicationContext();
  var dataDir = ctx.getFilesDir().getParentFile().getAbsolutePath();
  console.log('[*] data dir: ' + dataDir);

  var JFile = Java.use('java.io.File');
  var FileInputStream = Java.use('java.io.FileInputStream');
  var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
  var Base64 = Java.use('android.util.Base64');

  function walk(path, depth) {
    var f = JFile.$new(path);
    var kids = f.listFiles();
    if (kids === null) { return; }
    for (var i = 0; i < kids.length; i++) {
      var k = kids[i];
      var p = k.getAbsolutePath();
      if (k.isDirectory()) {
        console.log(Array(depth + 1).join('  ') + '[d] ' + p);
        if (depth < 4) { walk(p, depth + 1); }
      } else {
        console.log(Array(depth + 1).join('  ') + '[f] ' + p + '  (' + k.length() + ' bytes)');
      }
    }
  }
  walk(dataDir, 1);

  // dump every shared_prefs file as text
  var spDir = JFile.$new(dataDir + '/shared_prefs');
  var sps = spDir.listFiles();
  if (sps !== null) {
    for (var i = 0; i < sps.length; i++) {
      console.log('\n===== ' + sps[i].getName() + ' =====');
      console.log(readText(sps[i].getAbsolutePath()));
    }
  }

  function readText(path) {
    var fis = FileInputStream.$new(path);
    var bos = ByteArrayOutputStream.$new();
    var buf = Java.array('byte', new Array(4096).fill(0));
    var n;
    while ((n = fis.read(buf)) > 0) { bos.write(buf, 0, n); }
    fis.close();
    return Java.use('java.lang.String').$new(bos.toByteArray());
  }

  // base64 any binary file back to the host console
  function dumpB64(path) {
    var fis = FileInputStream.$new(path);
    var bos = ByteArrayOutputStream.$new();
    var buf = Java.array('byte', new Array(4096).fill(0));
    var n;
    while ((n = fis.read(buf)) > 0) { bos.write(buf, 0, n); }
    fis.close();
    console.log('[b64] ' + path + '\n' + Base64.encodeToString(bos.toByteArray(), 2));
  }
  rpc.exports = { dump: function (p) { Java.perform(function () { dumpB64(p); }); } };

  // ---- EncryptedSharedPreferences: read it through the app's own object --------
  try {
    var ESP = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
    ESP.getString.implementation = function (k, d) {
      var v = this.getString(k, d);
      console.log('[esp] ' + k + ' = ' + v);
      return v;
    };
    ESP.getAll.implementation = function () {
      var m = this.getAll();
      console.log('[esp] getAll -> ' + m.toString());
      return m;
    };
  } catch (e) { /* not used */ }

  // ---- plain SharedPreferences ------------------------------------------------
  var SPImpl = Java.use('android.app.SharedPreferencesImpl');
  SPImpl.getString.implementation = function (k, d) {
    var v = this.getString(k, d);
    console.log('[sp] getString("' + k + '") = ' + v);
    return v;
  };

  // ---- Keystore-backed crypto: log the plaintext, never the key ---------------
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[cipher] ' + this.getAlgorithm() + ' in=' + b64(input) + ' out=' + b64(out));
    return out;
  };

  // ---- SQLCipher passphrase ---------------------------------------------------
  try {
    var SQLCipher = Java.use('net.sqlcipher.database.SQLiteDatabase');
    SQLCipher.openOrCreateDatabase.overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log('[sqlcipher] args: ' + Array.prototype.slice.call(arguments).join(' | '));
        return ov.apply(this, arguments);
      };
    });
  } catch (e) { /* not used */ }

  function b64(bytes) {
    return Base64.encodeToString(bytes, 2);
  }
});
```

### objection

```bash
objection -g com.ctf.app explore
# inside the objection shell:
#   env                                  # print every app directory
#   ls /data/data/com.ctf.app/shared_prefs
#   file download /data/data/com.ctf.app/databases/app.db
#   android hooking list classes
#   android keystore list                # keystore aliases and key info
#   android keystore watch               # log keystore usage live
#   android sslpinning disable
#   sqlite connect /data/data/com.ctf.app/databases/app.db
#   sqlite schema
#   sqlite query "select * from users"
```

## Variants & pitfalls

- **You pulled the `.db` but the flag is missing** - it is in `app.db-wal`. Always pull
  all three files, or checkpoint first.
- **`run-as: package not debuggable`** - patch the manifest and reinstall, or use an
  emulator. Some OEM builds break `run-as` entirely.
- **`adb backup` returns a 0/24-byte file** - the app set `allowBackup="false"`, or the
  device is Android 12+. Not a bug in your command.
- **Backup contains only `no_backup`-excluded directories missing** by design; check
  `res/xml/backup_rules.xml` to see what was skipped.
- **Scoped storage (API 30+)** blocks `adb shell ls /sdcard/Android/data/<other pkg>` for
  the shell user on some builds; use `run-as` or root.
- **The "encrypted" prefs file is just base64** - check before assuming AES.
- **Keystore key extraction is impossible** by design when hardware-backed. Stop trying;
  hook `Cipher.doFinal` or call the app's own `decrypt()` from Frida.

## Tools

- `adb` (`exec-out`, `run-as`, `backup`, `bmgr`, `pull`).
- `sqlite3` - including `PRAGMA wal_checkpoint` and `.dump`.
- `frida` / `objection` - in-process reads and keystore watching.
- `abe` (Android Backup Extractor) - for password-encrypted `.ab` files.
- `strings` - the fastest path to a flag in a binary blob.

## References

- Android developer documentation: data and file storage overview, `SharedPreferences`,
  auto backup and `fullBackupContent` rules.
- androidx.security.crypto documentation for `EncryptedSharedPreferences` and `MasterKey`.
- Android Keystore system documentation on key extractability.
