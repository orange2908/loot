---
title: "Chainsaw (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "chainsaw", "forensics"]
summary: "Personal note: Chainsaw (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Chainsaw.md"
---

```bash
./chainsaw hunt ../../../Event-Logs --mapping ../../mappings/sigma-event-logs-all.yml -r ../../rules | tee ~/hackthebox/sherlocks/logjammer  
```

```bash
./chainsaw hunt -s sigma -m mappings/sigma-event-logs-all.yml Logs/ --full
```

```bash
./chainsaw hunt -s sigma -m mappings/sigma-event-logs-all.yml Logs/ --full --output output_folder --csv
```

---

*From your own notes: `Forensics/Chainsaw.md`*
