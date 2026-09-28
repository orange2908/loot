---
title: "Root check bypass (Mobile)"
category: "mobile"
type: "technique"
tags: ["my-notes", "personal", "root", "check", "bypass", "mobile"]
summary: "Personal note: Root check bypass (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/Root check bypass.md"
---

```js
Java.perform(function () {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.overload().implementation = function() {
        console.log("RootBeer isRooted check bypassed");
        return false;
    };

    var Candy = Java.use('com.android.hackon.foods.Candy$Companion');
    Candy.marshmallow.implementation = function() {
        console.log("Candy marshmallow check bypassed");
        return false;
    };
    Candy.gummy.implementation = function() {
        console.log("Candy gummy check bypassed");
        return false;
    };
    Candy.jelly.implementation = function() {
        console.log("Candy jelly check bypassed");
        return false;
    };
    Candy.sugar_free.implementation = function() {
        console.log("Candy sugar_free check bypassed");
        return false;
    };

    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var fileName = this.getName();
        if (fileName === 'su' || fileName === 'busybox') {
            console.log('Bypassing file exists check for: ' + fileName);
            return false;
        }
        return this.exists();
    };

    var Runtime = Java.use('java.lang.Runtime');
    var exec = Runtime.exec.overloads;
    exec.forEach(function(overload) {
        overload.implementation = function(cmd) {
            if (typeof cmd === 'string' && (cmd.includes('su') || cmd.includes('busybox'))) {
                console.log('Bypassing command execution: ' + cmd);
                return Java.use('java.lang.ProcessBuilder').$new('echo').start();
            } else if (Array.isArray(cmd) && (cmd.includes('su') || cmd.includes('busybox'))) {
                console.log('Bypassing command execution array: ' + cmd.join(' '));
                return Java.use('java.lang.ProcessBuilder').$new('echo').start();
            }
            return overload.apply(this, arguments);
        };
    });

    var MainActivity = Java.use('com.android.hackon.MainActivity');
    MainActivity.onCreate$lambda$0.implementation = function($usernameEditText, $passwordEditText, this$0, it) {
        console.log("Bypassing credential checks and directly launching PostLogin activity");
        var Intent = Java.use("android.content.Intent");
        var intent = Intent.$new(this$0, Java.use("com.android.hackon.PostLogin").class);
        this$0.startActivity(intent);
        this$0.finish();
    };

    console.log("PWNED!!!");
});
```

---

```js
Java.perform(function () {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.overload().implementation = function() {
        console.log("RootBeer isRooted check bypassed");
        return false;
    };

    var Candy = Java.use('com.android.hackon.foods.Candy$Companion');
    Candy.marshmallow.implementation = function() {
        console.log("[+] Candy marshmallow check bypassed");
        return false;
    };
    Candy.gummy.implementation = function() {
        console.log("[+] Candy gummy check bypassed");
        return false;
    };
    Candy.jelly.implementation = function() {
        console.log("[+] Candy jelly check bypassed");
        return false;
    };
    Candy.sugar_free.implementation = function() {
        console.log("[+] Candy sugar_free check bypassed");
        return false;
    };

    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var fileName = this.getName();
        if (fileName === 'su' || fileName === 'busybox') {
            console.log('[+] Bypassing file exists check for: ' + fileName);
            return false;
        }
        return this.exists();
    };

    var Runtime = Java.use('java.lang.Runtime');
    var exec = Runtime.exec.overloads;
    exec.forEach(function(overload) {
        overload.implementation = function(cmd) {
            if (typeof cmd === 'string' && (cmd.includes('su') || cmd.includes('busybox'))) {
                console.log('Bypassing command execution: ' + cmd);
                return Java.use('java.lang.ProcessBuilder').$new('echo').start();
            } else if (Array.isArray(cmd) && (cmd.includes('su') || cmd.includes('busybox'))) {
                console.log('Bypassing command execution array: ' + cmd.join(' '));
                return Java.use('java.lang.ProcessBuilder').$new('echo').start();
            }
            return overload.apply(this, arguments);
        };
    });

    var MainActivity = Java.use('com.android.hackon.MainActivity');
    MainActivity.onCreate$lambda$0.implementation = function($usernameEditText, $passwordEditText, this$0, it) {
        console.log("[+] Bypassing credential checks...");
        var Intent = Java.use("android.content.Intent");
        var intent = Intent.$new(this$0, Java.use("com.android.hackon.PostLogin").class);
        this$0.startActivity(intent);
        this$0.finish();
    };

    var Toast = Java.use("android.widget.Toast");
    var MainActivity = Java.use('com.android.hackon.MainActivity');
    MainActivity.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        this.onCreate(savedInstanceState);
        Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(context, text, duration) {
            console.log('Toast message: ' + text.toString());
            return this.makeText(context, text, duration);
        };
    };

    console.log("[+] PWNED! ! !");
});
```

---

*From your own notes: `Mobile/Root check bypass.md`*
