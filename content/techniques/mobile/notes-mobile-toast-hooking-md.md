---
title: "Toast hooking (Mobile)"
category: "mobile"
type: "technique"
tags: ["my-notes", "personal", "toast", "hooking", "mobile"]
summary: "Personal note: Toast hooking (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/Toast hooking.md"
---

```js
Java.perform(function () {
    var Toast = Java.use("android.widget.Toast");
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(context, text, duration) {
        console.log('[+] PWNED!!!: ' + text.toString());
        return this.makeText(context, text, duration);
    };

    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.overload().implementation = function() {
        return false;
    };

    var Candy = Java.use('com.android.hackon.foods.Candy$Companion');
    Candy.marshmallow.implementation = function() {
        return false;
    };
    Candy.gummy.implementation = function() {
        return true;
    };
    Candy.jelly.implementation = function() {
        return false;
    };
    Candy.sugar_free.implementation = function() {
        return false;
    }; 
});
```

---

*From your own notes: `Mobile/Toast hooking.md`*
