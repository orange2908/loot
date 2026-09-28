---
title: "Covert Timestamps python (random)"
category: "misc"
type: "technique"
tags: ["my-notes", "personal", "covert", "timestamps", "python", "random", "misc"]
summary: "Reference: Noted - Sherlocks HTB"
source:
  name: "Personal notes"
origin_path: "random/Covert Timestamps python.md"
---

#timestamps
**Reference:** Noted - Sherlocks HTB
```python
from datetime import datetime

original_file_last_modif_timestamp = -1354503710
original_file_last_modif_timestamp_high = 31047188

filetime = (original_file_last_modif_timestamp_high << 32) + (original_file_last_modif_timestamp & 0xFFFFFFFF)

unix_time = filetime / 10**7 - 11644473600

utc_datetime = datetime.utcfromtimestamp(unix_time)

print(utc_datetime)
```

---

```python
from datetime import datetime

timestamp = 1681986889.660179
datetime_utc = datetime.utcfromtimestamp(timestamp)

print(datetime_utc.strftime("%Y-%m-%d %H:%M:%S"))
```

---

*From your own notes: `random/Covert Timestamps python.md`*
