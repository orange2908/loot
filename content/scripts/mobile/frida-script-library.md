---
title: "Frida Script Library - Copy-Paste Hooks for Android and iOS"
category: mobile
subcategory: frida
type: script
tags: [frida, frida-server, objection, hooking, interceptor, java-perform, ssl-pinning, root-detection, jailbreak-detection, tracer, android, ios, javascript, instrumentation, rpc, memory-dump]
summary: "A library of ready-to-run Frida snippets: pinning and root bypasses, crypto and string loggers, tracers, native hooks and memory dumps."
tools: [frida, frida-tools, objection, node]
related: [android-frida-basics, android-ssl-pinning-bypass, android-root-detection-bypass, ios-frida-runtime, adb-objection-recipes]
---

## How to run

```bash
# 1. frida-server on the device must match the host frida version exactly
frida --version
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server -D'"

# 2. spawn (hooks land before Application.onCreate) or attach
frida -U -f com.ctf.app -l snippet.js --no-pause
frida -U -n com.ctf.app -l snippet.js
frida -U -p 1234 -l snippet.js

# 3. several scripts at once, logging to a file
frida -U -f com.ctf.app -l pinning.js -l root.js -l crypto.js --no-pause -o run.log

# 4. iOS is identical once frida-server (jailbroken) or FridaGadget is in place
frida -U -f com.ctf.app -l ios-jb.js --no-pause
```

## Snippet index

1. okhttp3 pinning bypass - 2. TrustManager bypass - 3. Conscrypt bypass -
4. WebViewClient SSL errors - 5. Root detection bypass - 6. String comparison logger -
7. Cipher logger - 8. MessageDigest / Mac logger - 9. SharedPreferences logger -
10. All-method class tracer - 11. Native hook by export - 12. Native hook by offset -
13. dlopen monitor - 14. WebView URL logger - 15. Intent logger -
16. Overloaded method hook - 17. Java field read/write - 18. Class enumeration -
19. Memory region dump - 20. Java.choose oracle - 21. Stack trace helper -
22. File access monitor - 23. iOS NSURLSession logger - 24. iOS jailbreak bypass -
25. iOS class/method tracer - 26. iOS NSString / NSLog logger - 27. rpc.exports -
28. Python driver.

---

### 1. okhttp3 certificate pinning bypass

Use when jadx shows `okhttp3.CertificatePinner` or a `Retrofit` client with a pin set.

```js
// okhttp-pinning.js - neutralise okhttp3 CertificatePinner and its hostname verifier
'use strict';

Java.perform(function () {
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function (host, peers) {
        console.log('[okhttp] CertificatePinner.check(' + host + ') bypassed');
      };
    if (CertificatePinner['check$okhttp']) {
      CertificatePinner['check$okhttp'].implementation = function (host, fn) {
        console.log('[okhttp] check$okhttp(' + host + ') bypassed');
      };
    }
  } catch (e) { console.log('[okhttp] CertificatePinner not present'); }

  try {
    var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
      .implementation = function (host, session) {
        console.log('[okhttp] verify(' + host + ') -> true');
        return true;
      };
  } catch (e) { console.log('[okhttp] OkHostnameVerifier not present'); }
});
```

### 2. TrustManager / SSLContext bypass

Use when the app builds its own `SSLContext` with a custom `X509TrustManager`.

```js
// trustmanager-bypass.js - replace every TrustManager with an accept-all one
'use strict';

Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');

  var TrustAll = Java.registerClass({
    name: 'com.ctf.TrustAll',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () { return []; }
    }
  });

  var init = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function (km, tm, sr) {
    console.log('[tls] SSLContext.init -> TrustAll injected');
    init.call(this, km, [TrustAll.$new()], sr);
  };
});
```

### 3. Conscrypt / platform trust bypass

Use on Android 7+ where the real verification happens inside Conscrypt.

```js
// conscrypt-bypass.js - defeat the platform trust manager used since android 7
'use strict';

Java.perform(function () {
  ['com.android.org.conscrypt.Platform', 'org.conscrypt.Platform'].forEach(function (cls) {
    try {
      var Platform = Java.use(cls);
      Platform.checkServerTrusted.overloads.forEach(function (ov) {
        ov.implementation = function () {
          console.log('[conscrypt] ' + cls + '.checkServerTrusted bypassed');
        };
      });
    } catch (e) { /* class absent on this api level */ }
  });

  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.verifyChain.implementation = function (untrusted, anchor, host, clientAuth, ocsp, sct) {
      console.log('[conscrypt] verifyChain(' + host + ') bypassed');
      return untrusted;
    };
    TMI.checkTrustedRecursive.implementation = function () {
      return Java.use('java.util.ArrayList').$new();
    };
  } catch (e) { /* older android */ }
});
```

### 4. WebViewClient SSL error bypass

Use when HTTPS content inside a WebView fails but the rest of the app is fine.

```js
// webview-ssl.js - make every WebView proceed past a certificate error
'use strict';

Java.perform(function () {
  var WebViewClient = Java.use('android.webkit.WebViewClient');
  WebViewClient.onReceivedSslError.overload(
    'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError')
    .implementation = function (view, handler, error) {
      console.log('[webview] SslError ' + error.toString() + ' -> proceed()');
      handler.proceed();
    };
});
```

### 5. Root detection bypass

Use when the app exits on launch complaining about root or an emulator.

```js
// root-bypass.js - hide su binaries, root packages, test-keys and dangerous props
'use strict';

var ROOT_PATHS = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
  '/system/app/Superuser.apk', '/data/local/su', '/system/xbin/busybox',
  '/system/bin/magisk', '/sbin/magisk', '/data/adb/magisk', '/data/adb/modules'];
var BAD_PKGS = ['com.topjohnwu.magisk', 'eu.chainfire.supersu',
  'com.noshufou.android.su', 'com.koushikdutta.superuser',
  'de.robv.android.xposed.installer'];

function looksRooted(s) {
  if (!s) { return false; }
  var low = ('' + s).toLowerCase();
  if (low.indexOf('magisk') !== -1 || low.indexOf('busybox') !== -1) { return true; }
  for (var i = 0; i < ROOT_PATHS.length; i++) {
    if (low.indexOf(ROOT_PATHS[i]) !== -1) { return true; }
  }
  return false;
}

Java.perform(function () {
  var JFile = Java.use('java.io.File');
  JFile.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (looksRooted(p)) { console.log('[root] File.exists(' + p + ') -> false'); return false; }
    return this.exists();
  };

  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overloads.forEach(function (ov) {
    ov.implementation = function () {
      var a = arguments[0];
      var desc = Array.isArray(a) ? a.join(' ') : '' + a;
      if (looksRooted(desc) || desc.indexOf('which su') !== -1) {
        console.log('[root] blocked exec: ' + desc);
        throw Java.use('java.io.IOException').$new('No such file or directory');
      }
      return ov.apply(this, arguments);
    };
  });

  var Build = Java.use('android.os.Build');
  Build.TAGS.value = 'release-keys';
  Build.FINGERPRINT.value = 'google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys';

  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
    if (BAD_PKGS.indexOf(pkg) !== -1) {
      console.log('[root] hiding ' + pkg);
      throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
    }
    return this.getPackageInfo(pkg, flags);
  };

  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    ['isRooted', 'detectRootManagementApps', 'checkForSuBinary', 'detectTestKeys',
     'checkForDangerousProps', 'checkForRWPaths', 'checkForMagiskBinary'].forEach(function (m) {
      if (RootBeer[m]) { RootBeer[m].implementation = function () { return false; }; }
    });
  } catch (e) { /* rootbeer not bundled */ }
});
```

### 6. java.lang.String comparison logger

The single most useful hook in a crackme: it prints the expected value.

```js
// string-compare.js - log every String.equals / contains / startsWith comparison
'use strict';

Java.perform(function () {
  var JString = Java.use('java.lang.String');
  var Log = Java.use('android.util.Log');
  var Throwable = Java.use('java.lang.Throwable');

  function trace() {
    return Log.getStackTraceString(Throwable.$new());
  }

  JString.equals.implementation = function (other) {
    var me = this.toString();
    var them = other === null ? 'null' : other.toString();
    if (me.length > 3 && me.length < 200) {
      console.log('[eq] "' + me + '" == "' + them + '"');
    }
    return this.equals(other);
  };

  JString.equalsIgnoreCase.implementation = function (other) {
    console.log('[eqi] "' + this.toString() + '" ~= "' + other + '"');
    return this.equalsIgnoreCase(other);
  };

  JString.contains.implementation = function (other) {
    var r = this.contains(other);
    if (r) { console.log('[contains] "' + this.toString() + '" has "' + other + '"'); }
    return r;
  };

  JString.startsWith.overload('java.lang.String').implementation = function (p) {
    var r = this.startsWith(p);
    if (r) { console.log('[startsWith] "' + this.toString() + '" ^ "' + p + '"\n' + trace()); }
    return r;
  };
});
```

### 7. javax.crypto.Cipher logger

Shows plaintext in and ciphertext out, plus the key and IV.

```js
// crypto-logger.js - log Cipher transformations, keys, IVs and doFinal input/output
'use strict';

Java.perform(function () {
  var Base64 = Java.use('android.util.Base64');

  function b64(bytes) {
    return bytes === null ? 'null' : Base64.encodeToString(bytes, 2);
  }
  function hex(bytes) {
    if (bytes === null) { return 'null'; }
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      s += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2);
    }
    return s;
  }

  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
    console.log('[crypto] Cipher.getInstance("' + t + '")');
    return this.getInstance(t);
  };

  Cipher.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[crypto] ' + this.getAlgorithm() +
                '\n  in  hex=' + hex(input) + '\n  in  b64=' + b64(input) +
                '\n  out hex=' + hex(out) + '\n  out b64=' + b64(out));
    return out;
  };

  Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (b, off, len) {
    var out = this.doFinal(b, off, len);
    console.log('[crypto] doFinal(off=' + off + ',len=' + len + ') out=' + b64(out));
    return out;
  };

  var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
    console.log('[crypto] SecretKeySpec alg=' + alg + ' key=' + hex(k) + ' (' + b64(k) + ')');
    return this.$init(k, alg);
  };

  var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
  IvParameterSpec.$init.overload('[B').implementation = function (iv) {
    console.log('[crypto] IV=' + hex(iv));
    return this.$init(iv);
  };
});
```

### 8. MessageDigest and Mac logger

Catches hash-based flag checks and HMAC request signing.

```js
// digest-logger.js - log MessageDigest and Mac (HMAC) inputs and outputs
'use strict';

Java.perform(function () {
  var Base64 = Java.use('android.util.Base64');
  var JString = Java.use('java.lang.String');

  function hex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) { s += ('0' + (b[i] & 0xff).toString(16)).slice(-2); }
    return s;
  }
  function asText(b) {
    try { return JString.$new(b).toString(); } catch (e) { return '<binary>'; }
  }

  var MD = Java.use('java.security.MessageDigest');
  MD.update.overload('[B').implementation = function (b) {
    console.log('[md] update(' + asText(b) + ')');
    return this.update(b);
  };
  MD.digest.overload().implementation = function () {
    var out = this.digest();
    console.log('[md] ' + this.getAlgorithm() + ' -> ' + hex(out));
    return out;
  };
  MD.digest.overload('[B').implementation = function (b) {
    var out = this.digest(b);
    console.log('[md] ' + this.getAlgorithm() + '("' + asText(b) + '") -> ' + hex(out));
    return out;
  };

  var Mac = Java.use('javax.crypto.Mac');
  Mac.doFinal.overload('[B').implementation = function (b) {
    var out = this.doFinal(b);
    console.log('[mac] ' + this.getAlgorithm() + '("' + asText(b) + '") -> ' + hex(out) +
                ' b64=' + Base64.encodeToString(out, 2));
    return out;
  };
});
```

### 9. SharedPreferences logger

Reveals tokens, feature flags and cached answers.

```js
// prefs-logger.js - log every SharedPreferences read and write
'use strict';

Java.perform(function () {
  var SPImpl = Java.use('android.app.SharedPreferencesImpl');
  SPImpl.getString.implementation = function (k, d) {
    var v = this.getString(k, d);
    console.log('[sp] getString("' + k + '") = ' + v);
    return v;
  };
  SPImpl.getBoolean.implementation = function (k, d) {
    var v = this.getBoolean(k, d);
    console.log('[sp] getBoolean("' + k + '") = ' + v);
    return v;
  };
  SPImpl.getInt.implementation = function (k, d) {
    var v = this.getInt(k, d);
    console.log('[sp] getInt("' + k + '") = ' + v);
    return v;
  };
  SPImpl.getAll.implementation = function () {
    var m = this.getAll();
    console.log('[sp] getAll -> ' + m.toString());
    return m;
  };

  var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  Editor.putString.implementation = function (k, v) {
    console.log('[sp] putString("' + k + '", "' + v + '")');
    return this.putString(k, v);
  };
  Editor.putBoolean.implementation = function (k, v) {
    console.log('[sp] putBoolean("' + k + '", ' + v + ')');
    return this.putBoolean(k, v);
  };
});
```

### 10. All-method tracer for a class

Hooks every declared method and every overload, printing args and return.

```js
// class-tracer.js - trace every method of one class
// edit TARGET, then: frida -U -f com.ctf.app -l class-tracer.js --no-pause
'use strict';

var TARGET = 'com.ctf.app.Checker';

Java.perform(function () {
  var Cls;
  try {
    Cls = Java.use(TARGET);
  } catch (e) {
    console.log('[trace] class not loaded: ' + TARGET);
    return;
  }

  var methods = Cls.class.getDeclaredMethods();
  console.log('[trace] ' + TARGET + ': ' + methods.length + ' declared methods');

  var names = {};
  methods.forEach(function (m) {
    var s = m.toString();
    var name = s.substring(s.lastIndexOf('.', s.indexOf('(')) + 1, s.indexOf('('));
    names[name] = true;
  });

  Object.keys(names).forEach(function (name) {
    var handle = Cls[name];
    if (!handle || !handle.overloads) { return; }
    handle.overloads.forEach(function (ov) {
      var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var shown = args.map(function (a) {
          try { return a === null ? 'null' : ('' + a).substring(0, 120); }
          catch (e) { return '<obj>'; }
        });
        var ret = ov.apply(this, args);
        console.log('[trace] ' + name + '(' + shown.join(', ') + ') = ' +
                    (ret === undefined ? 'void' : ('' + ret).substring(0, 200)) +
                    '   // (' + sig + ')');
        return ret;
      };
    });
  });

  // constructors too
  if (Cls.$init && Cls.$init.overloads) {
    Cls.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log('[trace] <init>(' + Array.prototype.slice.call(arguments).join(', ') + ')');
        return ov.apply(this, arguments);
      };
    });
  }
});
```

### 11. Native function hook by export name

For a statically registered JNI function, or any libc/library export.

```js
// native-export.js - hook a native function by module + export name
'use strict';

var LIB = 'libnative-lib.so';
var SYM = 'Java_com_ctf_app_Checker_verify';

function attach(addr) {
  console.log('[native] attaching at ' + addr);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      // JNI convention: args[0]=JNIEnv*, args[1]=jobject/jclass, args[2..]=real args
      this.env = args[0];
      var fnTable = args[0].readPointer();
      var getUtf = fnTable.add(169 * Process.pointerSize).readPointer();
      var f = new NativeFunction(getUtf, 'pointer', ['pointer', 'pointer', 'pointer']);
      var chars = f(args[0], args[2], NULL);
      this.arg = chars.isNull() ? '<null>' : chars.readUtf8String();
      console.log('[native] verify("' + this.arg + '")');
    },
    onLeave: function (ret) {
      console.log('[native] -> ' + ret);
      // ret.replace(ptr(1));   // uncomment to force success
    }
  });
}

var addr = Module.findExportByName(LIB, SYM);
if (addr !== null) {
  attach(addr);
} else {
  console.log('[native] ' + SYM + ' not found (dynamic RegisterNatives, or lib not loaded)');
}
```

### 12. Native function hook by module base + offset

When the library is stripped and Ghidra gave you an offset.

```js
// native-offset.js - hook an unexported function at base+offset (thumb: add 1 on arm32)
'use strict';

var LIB = 'libnative-lib.so';
var OFFSET = 0x1a2c4;

function hookOffset() {
  var mod = Process.findModuleByName(LIB);
  if (mod === null) { return false; }
  var addr = mod.base.add(OFFSET);
  console.log('[off] ' + LIB + ' base=' + mod.base + ' target=' + addr);

  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.a0 = args[0];
      this.a1 = args[1];
      console.log('[off] enter a0=' + args[0] + ' a1=' + args[1] +
                  ' a2=' + args[2] + ' a3=' + args[3]);
      try { console.log('[off] a0 as string: ' + args[0].readCString()); } catch (e) { /* not a string */ }
    },
    onLeave: function (ret) {
      console.log('[off] leave ret=' + ret);
    }
  });
  return true;
}

if (!hookOffset()) {
  var dl = Module.findExportByName(null, 'android_dlopen_ext') ||
           Module.findExportByName(null, 'dlopen');
  Interceptor.attach(dl, {
    onEnter: function (args) { this.p = args[0].readCString(); },
    onLeave: function () { if (this.p && this.p.indexOf(LIB) !== -1) { hookOffset(); } }
  });
}
```

### 13. dlopen monitor

Logs every native library the app loads, and lets you hook one the moment it appears.

```js
// dlopen-monitor.js - watch native library loading and run a callback on a match
'use strict';

var WATCH = 'libnative-lib.so';

function onLibLoaded(path) {
  console.log('[dlopen] loaded ' + path);
  var mod = Process.findModuleByName(WATCH);
  if (mod !== null) {
    console.log('[dlopen] ' + WATCH + ' base=' + mod.base + ' size=' + mod.size);
    Module.enumerateExports(WATCH).slice(0, 30).forEach(function (e) {
      console.log('   export ' + e.type + ' ' + e.name + ' @ ' + e.address);
    });
  }
}

['android_dlopen_ext', 'dlopen', '__loader_dlopen'].forEach(function (sym) {
  var addr = Module.findExportByName(null, sym);
  if (addr === null) { return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
    },
    onLeave: function (retval) {
      if (this.path === null) { return; }
      console.log('[dlopen] ' + sym + '("' + this.path + '") -> ' + retval);
      if (this.path.indexOf(WATCH) !== -1) { onLibLoaded(this.path); }
    }
  });
});
```

### 14. WebView URL logger

Every URL, every injected bridge, and every evaluated script.

```js
// webview-logger.js - log WebView navigation, bridges and javascript evaluation
'use strict';

Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');

  WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
    console.log('[wv] loadUrl: ' + url);
    return this.loadUrl(url);
  };
  WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (u, h) {
    console.log('[wv] loadUrl+headers: ' + u + ' ' + h);
    return this.loadUrl(u, h);
  };
  WebView.loadData.implementation = function (data, mime, enc) {
    console.log('[wv] loadData(' + mime + '): ' + ('' + data).substring(0, 200));
    return this.loadData(data, mime, enc);
  };
  WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
    console.log('[wv] loadDataWithBaseURL base=' + base);
    return this.loadDataWithBaseURL(base, data, mime, enc, hist);
  };
  WebView.evaluateJavascript.implementation = function (js, cb) {
    console.log('[wv] eval: ' + ('' + js).substring(0, 200));
    return this.evaluateJavascript(js, cb);
  };
  WebView.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[wv] addJavascriptInterface("' + name + '") -> ' + obj.$className);
    return this.addJavascriptInterface(obj, name);
  };
});
```

### 15. Intent logger

See which components the app starts and what extras it reads.

```js
// intent-logger.js - log intent construction, extras and component launches
'use strict';

Java.perform(function () {
  var Intent = Java.use('android.content.Intent');

  Intent.getStringExtra.implementation = function (k) {
    var v = this.getStringExtra(k);
    console.log('[intent] getStringExtra("' + k + '") = ' + v);
    return v;
  };
  Intent.getIntExtra.implementation = function (k, d) {
    var v = this.getIntExtra(k, d);
    console.log('[intent] getIntExtra("' + k + '") = ' + v);
    return v;
  };
  Intent.setData.implementation = function (uri) {
    console.log('[intent] setData(' + uri + ')');
    return this.setData(uri);
  };
  Intent.parseUri.implementation = function (uri, flags) {
    console.log('[intent] parseUri("' + uri + '") <-- redirection candidate');
    return this.parseUri(uri, flags);
  };

  var Activity = Java.use('android.app.Activity');
  Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
    console.log('[intent] startActivity ' + i.toString() + ' comp=' + i.getComponent());
    return this.startActivity(i);
  };

  var ContextImpl = Java.use('android.app.ContextImpl');
  ContextImpl.startService.implementation = function (i) {
    console.log('[intent] startService ' + i.toString());
    return this.startService(i);
  };
});
```

### 16. Hooking an overloaded method

The syntax people get wrong most often.

```js
// overload.js - pick one specific overload, and enumerate the rest
'use strict';

Java.perform(function () {
  var Crypto = Java.use('com.ctf.app.Crypto');

  // list every overload with its signature, so you can pick the right one
  Crypto.decrypt.overloads.forEach(function (ov, i) {
    var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
    console.log('[ovl] decrypt#' + i + '(' + sig + ') -> ' + ov.returnType.className);
  });

  // hook exactly one
  Crypto.decrypt.overload('java.lang.String', 'int').implementation = function (s, mode) {
    var r = this.decrypt(s, mode);
    console.log('[ovl] decrypt("' + s + '", ' + mode + ') = ' + r);
    return r;
  };

  // byte[] and arrays use JNI descriptors
  Crypto.process.overload('[B').implementation = function (buf) {
    console.log('[ovl] process(byte[' + buf.length + '])');
    return this.process(buf);
  };
  Crypto.pick.overload('[Ljava.lang.String;', 'int').implementation = function (arr, n) {
    console.log('[ovl] pick(' + arr.join(',') + ', ' + n + ')');
    return this.pick(arr, n);
  };
});
```

### 17. Reading and writing Java fields

Instance fields, static fields and the `_name` collision rule.

```js
// fields.js - read and write instance and static fields
'use strict';

Java.perform(function () {
  var Config = Java.use('com.ctf.app.Config');

  // static field: read then overwrite
  console.log('[field] static DEBUG = ' + Config.DEBUG.value);
  Config.DEBUG.value = true;
  console.log('[field] static API = ' + Config.API_URL.value);
  Config.API_URL.value = 'http://10.0.2.2:8000/';

  // instance fields on a live object
  Java.choose('com.ctf.app.Session', {
    onMatch: function (inst) {
      console.log('[field] token = ' + inst.token.value);
      // if the class has both a field and a method called "token", use the underscore form
      if (inst._token !== undefined) {
        console.log('[field] (underscore form) = ' + inst._token.value);
      }
      inst.isAdmin.value = true;
      console.log('[field] isAdmin forced to true');
    },
    onComplete: function () { console.log('[field] scan done'); }
  });

  // dump every field of a class using java reflection
  var fields = Config.class.getDeclaredFields();
  fields.forEach(function (f) {
    f.setAccessible(true);
    try {
      console.log('[field] ' + f.getName() + ' = ' + f.get(null));
    } catch (e) { /* non-static needs an instance */ }
  });
});
```

### 18. Enumerating loaded classes and classloaders

Find the obfuscated class you cannot name.

```js
// enumerate.js - list loaded classes, filter by substring, and switch classloaders
'use strict';

Java.perform(function () {
  var needle = 'ctf';
  var all = Java.enumerateLoadedClassesSync();
  console.log('[enum] ' + all.length + ' loaded classes');

  var hits = all.filter(function (n) { return n.toLowerCase().indexOf(needle) !== -1; });
  hits.slice(0, 60).forEach(function (n) { console.log('  ' + n); });
  console.log('[enum] ' + hits.length + ' match "' + needle + '"');

  // methods of the first hit
  if (hits.length > 0) {
    try {
      var C = Java.use(hits[0]);
      C.class.getDeclaredMethods().forEach(function (m) { console.log('    ' + m.toString()); });
    } catch (e) { console.log('[enum] cannot use ' + hits[0] + ': ' + e); }
  }

  // packed apps load the real dex in a second classloader
  Java.enumerateClassLoaders({
    onMatch: function (loader) {
      console.log('[enum] classloader: ' + loader.toString());
      try {
        loader.loadClass('com.ctf.app.Checker');
        Java.classFactory.loader = loader;
        console.log('[enum] -> switched to this loader');
      } catch (e) { /* not this one */ }
    },
    onComplete: function () { console.log('[enum] loader scan done'); }
  });
});
```

### 19. Dumping memory regions

Carve the flag straight out of the heap.

```js
// memdump.js - scan and dump readable memory; also grep it for a pattern
'use strict';

var PATTERN = 'flag{';
var MAX_DUMP = 32 * 1024 * 1024;

function scanForString(text) {
  var pattern = '';
  for (var i = 0; i < text.length; i++) {
    pattern += (i ? ' ' : '') + ('0' + text.charCodeAt(i).toString(16)).slice(-2);
  }
  var ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true });
  console.log('[mem] scanning ' + ranges.length + ' ranges for "' + text + '"');
  ranges.forEach(function (r) {
    try {
      Memory.scanSync(r.base, r.size, pattern).forEach(function (hit) {
        var s = hit.address.readCString(200);
        console.log('[mem] ' + hit.address + ' : ' + s);
      });
    } catch (e) { /* unreadable */ }
  });
}

function dumpRanges(prot) {
  var total = 0;
  Process.enumerateRanges({ protection: prot, coalesce: true }).forEach(function (r) {
    if (total > MAX_DUMP) { return; }
    var name = r.file ? r.file.path.split('/').pop() : 'anon';
    var path = '/data/local/tmp/dump_' + r.base.toString(16) + '_' + r.size + '_' + name + '.bin';
    try {
      var bytes = r.base.readByteArray(r.size);
      var f = new File(path, 'wb');
      f.write(bytes);
      f.flush();
      f.close();
      total += r.size;
      console.log('[mem] ' + path);
    } catch (e) { /* skip guarded pages */ }
  });
  console.log('[mem] dumped ' + total + ' bytes; adb pull /data/local/tmp/');
}

scanForString(PATTERN);
// dumpRanges('rw-');   // uncomment for a full heap dump

// hexdump a single address
function peek(addrStr, len) {
  var p = ptr(addrStr);
  console.log(hexdump(p, { length: len || 128, header: true, ansi: false }));
}
rpc.exports = { peek: peek, scan: scanForString, dump: dumpRanges };
```

### 20. Java.choose as an oracle

Use a live object to brute a prefix-checking validator.

```js
// choose-oracle.js - find a live instance and drive its checker
'use strict';

Java.perform(function () {
  var ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789_{}-';

  Java.choose('com.ctf.app.Checker', {
    onMatch: function (inst) {
      console.log('[oracle] live instance @ ' + inst.$handle);
      var known = 'flag{';
      for (var pos = 0; pos < 48; pos++) {
        var found = false;
        for (var i = 0; i < ALPHABET.length; i++) {
          if (inst.verifyPrefix(known + ALPHABET[i])) {
            known += ALPHABET[i];
            console.log('[oracle] ' + known);
            found = true;
            break;
          }
        }
        if (!found) { break; }
      }
      console.log('[oracle] done: ' + known);
      return 'stop';
    },
    onComplete: function () { console.log('[oracle] scan complete'); }
  });
});
```

### 21. Stack trace helper

Answer "who called this?" from inside any hook.

```js
// stacktrace.js - print a java stack trace, and a native backtrace
'use strict';

Java.perform(function () {
  var Log = Java.use('android.util.Log');
  var Throwable = Java.use('java.lang.Throwable');

  function javaStack() {
    return Log.getStackTraceString(Throwable.$new());
  }

  var JString = Java.use('java.lang.String');
  JString.equals.implementation = function (other) {
    var me = this.toString();
    if (me.indexOf('flag') !== -1 || me.length === 32) {
      console.log('[stack] "' + me + '".equals("' + other + '")\n' + javaStack());
    }
    return this.equals(other);
  };
});

// native side: backtrace from inside an Interceptor
var open = Module.findExportByName('libc.so', 'open');
if (open !== null) {
  Interceptor.attach(open, {
    onEnter: function (args) {
      var p = args[0].readCString();
      if (p && p.indexOf('/data/data') === 0) {
        console.log('[stack] open("' + p + '")\n' +
          Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
      }
    }
  });
}
```

### 22. File access monitor

Which files does the app touch, and in what order.

```js
// file-monitor.js - log java and native file access
'use strict';

Java.perform(function () {
  var JFile = Java.use('java.io.File');
  JFile.$init.overload('java.lang.String').implementation = function (p) {
    console.log('[file] new File("' + p + '")');
    return this.$init(p);
  };
  JFile.$init.overload('java.lang.String', 'java.lang.String')
    .implementation = function (parent, child) {
      console.log('[file] new File("' + parent + '", "' + child + '")');
      return this.$init(parent, child);
    };

  var FIS = Java.use('java.io.FileInputStream');
  FIS.$init.overload('java.io.File').implementation = function (f) {
    console.log('[file] read ' + f.getAbsolutePath());
    return this.$init(f);
  };

  var FOS = Java.use('java.io.FileOutputStream');
  FOS.$init.overload('java.io.File').implementation = function (f) {
    console.log('[file] write ' + f.getAbsolutePath());
    return this.$init(f);
  };
});

['open', 'openat', 'fopen'].forEach(function (fn) {
  var addr = Module.findExportByName('libc.so', fn);
  if (addr === null) { return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      var idx = (fn === 'openat') ? 1 : 0;
      try {
        var p = args[idx].readCString();
        if (p && p.indexOf('/proc') !== 0) { console.log('[native-file] ' + fn + '("' + p + '")'); }
      } catch (e) { /* not a path */ }
    }
  });
});
```

### 23. iOS NSURLSession logger

Every outbound request with headers and body.

```js
// ios-net.js - log NSURLSession requests and responses
'use strict';

if (ObjC.available) {
  var NSString = ObjC.classes.NSString;

  function bodyText(data) {
    if (!data || data.isNull()) { return ''; }
    return NSString.alloc().initWithData_encoding_(data, 4).toString();
  }

  ['- dataTaskWithRequest:completionHandler:', '- dataTaskWithRequest:',
   '- uploadTaskWithRequest:fromData:completionHandler:'].forEach(function (sel) {
    var m = ObjC.classes.NSURLSession[sel];
    if (!m) { return; }
    Interceptor.attach(m.implementation, {
      onEnter: function (args) {
        var req = new ObjC.Object(args[2]);
        console.log('\n[net] ' + req.HTTPMethod() + ' ' + req.URL().absoluteString());
        var h = req.allHTTPHeaderFields();
        if (h) { console.log('[net] headers ' + h.toString()); }
        var b = bodyText(req.HTTPBody());
        if (b) { console.log('[net] body ' + b.substring(0, 500)); }
      }
    });
  });

  var conn = ObjC.classes.NSURLConnection;
  if (conn && conn['+ sendSynchronousRequest:returningResponse:error:']) {
    Interceptor.attach(conn['+ sendSynchronousRequest:returningResponse:error:'].implementation, {
      onEnter: function (args) {
        console.log('[net] sync ' + new ObjC.Object(args[2]).URL().absoluteString());
      }
    });
  }
}
```

### 24. iOS jailbreak detection bypass

```js
// ios-jb.js - hide the jailbreak from file, url, fork and ptrace checks
'use strict';

var JB = ['/applications/cydia.app', '/applications/sileo.app', '/library/mobilesubstrate',
  '/usr/sbin/sshd', '/usr/bin/ssh', '/etc/apt', '/bin/bash', '/bin/sh', '/var/jb',
  '/private/var/lib/apt', '/private/var/lib/cydia', '/.installed_unc0ver', '/taurine',
  '/electra', '/chimera', 'frida', 'cynject', 'libcycript', 'substrate', 'libhooker'];

function isJB(s) {
  if (!s) { return false; }
  var low = ('' + s).toLowerCase();
  for (var i = 0; i < JB.length; i++) {
    if (low.indexOf(JB[i]) !== -1) { return true; }
  }
  return false;
}

['stat', 'stat64', 'lstat', 'access', 'fopen', 'open', 'opendir'].forEach(function (fn) {
  var addr = Module.findExportByName(null, fn);
  if (addr === null) { return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try { this.bad = isJB(args[0].readUtf8String()); } catch (e) { this.bad = false; }
    },
    onLeave: function (ret) {
      if (this.bad) { ret.replace(fn === 'fopen' || fn === 'opendir' ? ptr(0) : ptr(-1)); }
    }
  });
});

['fork', 'vfork'].forEach(function (fn) {
  var a = Module.findExportByName(null, fn);
  if (a !== null) {
    Interceptor.replace(a, new NativeCallback(function () { return -1; }, 'int', []));
  }
});

var ptrace = Module.findExportByName(null, 'ptrace');
if (ptrace !== null) {
  Interceptor.replace(ptrace, new NativeCallback(function () { return 0; },
    'int', ['int', 'int', 'pointer', 'int']));
}

if (ObjC.available) {
  Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) { this.bad = isJB(new ObjC.Object(args[2]).toString()); },
    onLeave: function (ret) { if (this.bad) { ret.replace(ptr(0)); } }
  });
  Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
    onEnter: function (args) {
      this.bad = /^(cydia|sileo|zbra|filza)/
        .test(new ObjC.Object(args[2]).absoluteString().toString());
    },
    onLeave: function (ret) { if (this.bad) { ret.replace(ptr(0)); } }
  });
}
console.log('[+] ios jailbreak bypass installed');
```

### 25. iOS class and method tracer

```js
// ios-tracer.js - trace every method of every class matching a prefix
'use strict';

var PREFIX = 'CTF';

if (ObjC.available) {
  var classes = Object.keys(ObjC.classes).filter(function (n) {
    return n.indexOf(PREFIX) === 0 || n.indexOf('.') !== -1;
  });
  console.log('[trace] ' + classes.length + ' candidate classes');

  classes.forEach(function (cname) {
    var cls = ObjC.classes[cname];
    var methods;
    try { methods = cls.$ownMethods; } catch (e) { return; }
    methods.forEach(function (sel) {
      try {
        Interceptor.attach(cls[sel].implementation, {
          onEnter: function (args) {
            this.sel = cname + ' ' + sel;
            var parts = [];
            var argc = (sel.match(/:/g) || []).length;
            for (var i = 0; i < argc && i < 4; i++) {
              try {
                var o = new ObjC.Object(args[2 + i]);
                parts.push(o.toString().substring(0, 80));
              } catch (e) { parts.push('' + args[2 + i]); }
            }
            console.log('[>] ' + this.sel + ' (' + parts.join(' | ') + ')');
          },
          onLeave: function (ret) {
            console.log('[<] ' + this.sel + ' = ' + ret);
          }
        });
      } catch (e) { /* some selectors cannot be hooked */ }
    });
  });
  console.log('[trace] installed');
}
```

### 26. iOS NSString and NSLog logger

```js
// ios-strings.js - log NSString comparisons and every NSLog
'use strict';

if (ObjC.available) {
  var isEqual = ObjC.classes.NSString['- isEqualToString:'];
  var orig = new NativeFunction(isEqual.implementation, 'bool',
                                ['pointer', 'pointer', 'pointer']);
  isEqual.implementation = ObjC.implement(isEqual, function (self, sel, other) {
    var a = new ObjC.Object(self).toString();
    var b = new ObjC.Object(other).toString();
    if (a.length > 3 && a.length < 120) { console.log('[cmp] "' + a + '" == "' + b + '"'); }
    return orig(self, sel, other);
  });

  var nslog = Module.findExportByName('Foundation', 'NSLog');
  if (nslog !== null) {
    Interceptor.attach(nslog, {
      onEnter: function (args) {
        console.log('[NSLog] ' + new ObjC.Object(args[0]).toString());
      }
    });
  }

  var defaults = ObjC.classes.NSUserDefaults['- objectForKey:'];
  Interceptor.attach(defaults.implementation, {
    onEnter: function (args) { this.k = new ObjC.Object(args[2]).toString(); },
    onLeave: function (ret) {
      if (!ret.isNull()) {
        console.log('[def] ' + this.k + ' = ' + new ObjC.Object(ret).toString());
      }
    }
  });
}
```

### 27. rpc.exports - drive the app from Python

```js
// rpc-agent.js - expose app functionality to the host for scripted brute forcing
'use strict';

rpc.exports = {
  check: function (candidate) {
    var result = false;
    Java.perform(function () {
      var Checker = Java.use('com.ctf.app.Checker');
      result = Checker.$new().verify(candidate);
    });
    return result;
  },
  classes: function (prefix) {
    var out = [];
    Java.perform(function () {
      Java.enumerateLoadedClassesSync().forEach(function (n) {
        if (n.indexOf(prefix) === 0) { out.push(n); }
      });
    });
    return out;
  },
  readfile: function (path) {
    var data = null;
    Java.perform(function () {
      var FIS = Java.use('java.io.FileInputStream');
      var BAOS = Java.use('java.io.ByteArrayOutputStream');
      var Base64 = Java.use('android.util.Base64');
      var fis = FIS.$new(path);
      var bos = BAOS.$new();
      var buf = Java.array('byte', new Array(4096).fill(0));
      var n;
      while ((n = fis.read(buf)) > 0) { bos.write(buf, 0, n); }
      fis.close();
      data = Base64.encodeToString(bos.toByteArray(), 2);
    });
    return data;
  },
  peek: function (addr, len) {
    return hexdump(ptr(addr), { length: len, header: true, ansi: false });
  }
};
```

### 28. Python driver for the RPC agent

```python
#!/usr/bin/env python3
"""frida_rpc.py - load rpc-agent.js into a target and drive it from python.

Usage:
  python3 frida_rpc.py com.ctf.app rpc-agent.js --brute
  python3 frida_rpc.py com.ctf.app rpc-agent.js --classes com.ctf
  python3 frida_rpc.py com.ctf.app rpc-agent.js --read /data/data/com.ctf.app/shared_prefs/p.xml
"""
from __future__ import annotations

import argparse
import base64
import sys
import time

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_{}-"


def on_message(message: dict, data: bytes | None) -> None:
    if message.get("type") == "send":
        print("[send]", message.get("payload"))
    elif message.get("type") == "error":
        print("[error]", message.get("stack", message.get("description")), file=sys.stderr)


def load(package: str, script_path: str, attach: bool):
    import frida  # type: ignore

    device = frida.get_usb_device(timeout=10)
    pid = None
    if attach:
        session = device.attach(package)
    else:
        pid = device.spawn([package])
        session = device.attach(pid)
    with open(script_path, encoding="utf-8") as fh:
        script = session.create_script(fh.read())
    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)
        time.sleep(1.0)
    return session, script


def brute(script, prefix: str = "flag{") -> str:
    known = prefix
    for _ in range(64):
        for ch in ALPHABET:
            if script.exports_sync.check(known + ch):
                known += ch
                print("[+]", known)
                break
        else:
            break
    return known


def main() -> int:
    ap = argparse.ArgumentParser(description="frida rpc driver")
    ap.add_argument("package")
    ap.add_argument("script")
    ap.add_argument("--attach", action="store_true")
    ap.add_argument("--brute", action="store_true")
    ap.add_argument("--classes")
    ap.add_argument("--read")
    args = ap.parse_args()

    try:
        session, script = load(args.package, args.script, args.attach)
    except ImportError:
        print("pip install frida-tools", file=sys.stderr)
        return 1

    if args.brute:
        print("[done]", brute(script))
    if args.classes:
        for name in script.exports_sync.classes(args.classes):
            print(name)
    if args.read:
        blob = script.exports_sync.readfile(args.read)
        sys.stdout.buffer.write(base64.b64decode(blob))
    if not (args.brute or args.classes or args.read):
        print("[*] script loaded; ctrl-c to detach")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    session.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```
