---
title: "Bypass.Js (Mobile)"
category: "mobile"
subcategory: "runtime"
type: "technique"
tags: ["my-notes", "personal", "frida", "bypass", "mobile"]
summary: "Personal note: Bypass.Js (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/bypass.js.md"
---

```js
/**
 * Frida Bypass Script for Spooky Welcome (jio.spookyctf.welcome)
 * Bypasses root, jailbreak, emulator, and anti-frida checks.
 */

Java.perform(function () {
    console.log("[*] Root Bypass Script Loaded");

    function hookClass(className, hookCallback) {
        try {
            var clazz = Java.use(className);
            hookCallback(clazz);
            console.log("[+] Successfully hooked: " + className);
        } catch (e) {
            console.log("[!] Failed to hook " + className + ": " + e.message);
        }
    }

    // 1. Hook MethodChannel Handler in rjsniffer plugin
    hookClass("com.emrys.rjsniffer.rjsniffer.a", function (RjsnifferPlugin) {
        RjsnifferPlugin.n.overload("C.a", "O.l").implementation = function (call, result) {
            // Access the field 'c' (the method name) more robustly
            var method = "unknown";
            try {
                // Using reflection to be safe
                var fieldC = call.getClass().getDeclaredField("c");
                fieldC.setAccessible(true);
                method = fieldC.get(call).toString();
            } catch (e) {
                // Fallback to direct access if reflection fails
                if (call.c && call.c.value) method = call.c.value.toString();
            }

            console.log("[i] MethodChannel Call: " + method);

            if (method.indexOf("runprog") !== -1) {
                console.log("[+] Bypassing root/emulator check: " + method);
                // Return false for any root/emulator check
                result.d(Java.use("java.lang.Boolean").$new(false));
                return;
            }
            this.n(call, result);
        };
    });

    // 2. Hook the Isolated Service Binder (com.emrys.rjsniffer.rjsniffer.b)
    // This class's a() method performs low-level root checks.
    hookClass("com.emrys.rjsniffer.rjsniffer.b", function (ServiceB) {
        ServiceB.a.implementation = function () {
            console.log("[+] Isolated service root check (a) bypassed");
            return false;
        };
    });

    // 3. Hook RootInspector Utility Classes (D.b)
    hookClass("D.b", function (RootInspector) {
        try {
            RootInspector.m.implementation = function (binary) {
                console.log("[i] RootInspector checking binary: " + binary);
                return false;
            };
        } catch (e) { console.log("[!] D.b.m failed: " + e.message); }

        ["o", "q", "r", "s"].forEach(function (methodName) {
            try {
                RootInspector[methodName].implementation = function () {
                    console.log("[i] RootInspector hooking " + methodName);
                    return false;
                };
            } catch (e) { }
        });
    });

    // 4. Hook standard system property checks
    hookClass("android.os.SystemProperties", function (SystemProperties) {
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            var val = this.get(key);
            if (key === "ro.debuggable" || key === "ro.secure" || key === "ro.build.tags") {
                console.log("[i] Bypassing SystemProperties.get: " + key);
                if (key === "ro.debuggable") return "0";
                if (key === "ro.secure") return "1";
                if (key === "ro.build.tags") return "release-keys";
            }
            return val;
        };
    });

    // 5. Hook Native Library methods
    var nativeLibName = "librjsniffer-lib.so";
    function hookNative() {
        var module = Process.findModuleByName(nativeLibName);
        if (module) {
            console.log("[*] Native module found: " + nativeLibName);
            var exports = Module.enumerateExports(nativeLibName);
            exports.forEach(function (exp) {
                if (exp.name.indexOf("isMagiskPresentNative") !== -1 || exp.name.indexOf("checkFridaByPort") !== -1) {
                    Interceptor.attach(exp.address, {
                        onLeave: function (retval) {
                            console.log("[+] Native check bypassed: " + exp.name);
                            retval.replace(0);
                        }
                    });
                }
            });
        }
    }

    hookNative();

    try {
        var System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (name) {
            this.loadLibrary(name);
            if (name === "rjsniffer-lib") {
                console.log("[*] rjsniffer-lib loaded, applying native hooks...");
                hookNative();
            }
        }
    } catch (e) { }
});
```

```bash
(macbook) ➜  tmp frida -U -l bypass.js -f jio.spookyctf.welcome
```

---

*From your own notes: `Mobile/bypass.js.md`*
