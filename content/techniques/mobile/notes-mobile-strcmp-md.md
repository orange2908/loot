---
title: "Strcmp (Mobile)"
category: "mobile"
type: "technique"
tags: ["my-notes", "personal", "strcmp", "mobile"]
summary: "Personal note: Strcmp (Mobile)."
source:
  name: "Personal notes"
origin_path: "Mobile/strcmp.md"
---

```js
// Find the module containing strcmp
var libangler = Module.findBaseAddress("libangler.so");

// Find the address of strcmp within libangler.so
var strcmpPtr = Module.findExportByName(null, "strcmp");

// Intercept strcmp calls
Interceptor.attach(strcmpPtr, {
    onEnter: function(args) {
        // Get the compared strings
        var str1 = Memory.readUtf8String(args[0]);
        var str2 = Memory.readUtf8String(args[1]);

        // Log the compared strings
        console.log("strcmp called with strings:", str1, str2);
    }
});
```

---

*From your own notes: `Mobile/strcmp.md`*
