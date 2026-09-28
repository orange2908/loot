---
title: "Mount a EWFExpert WitnessEnCase image file format .E01 (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "mount", "ewfexpert", "witnessencase", "image", "file", "format", "forensics"]
summary: "https://ctftime.org/writeup/22951"
source:
  name: "Personal notes"
origin_path: "Forensics/Mount a EWFExpert WitnessEnCase image file format .E01.md"
---

```
mkdir rawimage
```

```
sudo ewfmount Image.E01 rawimage/
```

```
mkdir mountpoint
```

```
sudo mount ./rawimage/ewf1 ./mountpoint -o ro,loop,show_sys_files,streams_interace=windows
```

```
cd mountpoint/
```

```
ls -lah
```
### Unmount
```
umount /mountpoint
```
### Reference
https://ctftime.org/writeup/22951

---

*From your own notes: `Forensics/Mount a EWFExpert WitnessEnCase image file format .E01.md`*
