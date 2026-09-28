---
title: "MemProcFS (Forensics)"
category: "forensics"
subcategory: "memory"
type: "technique"
tags: ["my-notes", "personal", "memory-forensics", "fpga", "memprocfs", "forensics"]
summary: "Personal note: MemProcFS (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/MemProcFS.md"
---

- mount the memory dump file as default M:

```
memprocfs.exe -device c:\temp\win10x64-dump.raw
```

- mount the memory dump file as default M: with extra verbosity:

```
memprocfs.exe -device c:\temp\win10x64-dump.raw -v
```

- mount the memory dump file as default M: and start forensics mode:

```
memprocfs.exe -device c:\temp\win10x64-dump.raw -forensic 1
```

- mount the memory dump file as /home/pi/mnt/ on Linux:

```
./memprocfs -mount /home/pi/linux -device /dumps/win10x64-dump.raw
```

- mount the memory dump file as S:

```
memprocfs.exe -mount s -device c:\temp\win10x64-dump.raw
```

- mount live target memory, in verbose read-only mode, with DumpIt in /LIVEKD mode:

```
DumpIt.exe /LIVEKD /A memprocfs.exe /C "-v"
```

- mount live target memory, in read-only mode, with WinPMEM driver:

```
memprocfs.exe -device pmem
```

- mount live target memory, in read/write mode, with PCILeech FPGA memory acquisition device:

```
memprocfs.exe -device fpga -memmap auto
```

- mount a memory dump with a corresponding page files:

```
memprocfs.exe -device unknown-x64-dump.raw -pagefile0 pagefile.sys -pagefile1 swapfile.sys
```

# MAIN
```bash
sudo mkdir /mnt/memdump && sudo ~/tools/forensics/memprocfs/memprocfs -mount /mnt/memdump -device DFIRLABS.raw -forensic 1
```

---

*From your own notes: `Forensics/MemProcFS.md`*
