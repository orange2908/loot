---
title: "Web tricks (Web)"
category: "web"
subcategory: "file-upload"
type: "technique"
tags: ["my-notes", "personal", "file-upload", "web", "tricks"]
summary: "You have file upload, but .php files are disallowed?"
source:
  name: "Personal notes"
origin_path: "Web/Web tricks.md"
---

You have file upload, but `.php` files are disallowed? What if you could tell Apache to interpret an arbitrary file extension as `.php`? Upload the following as a `.htaccess`, and now `.cth` is as good as `.php`!
```php
"AddType application/x-httpd-php .cth"
```

---

*From your own notes: `Web/Web tricks.md`*
