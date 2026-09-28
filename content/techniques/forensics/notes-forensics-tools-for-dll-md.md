---
title: "Tools for DLL (Forensics)"
category: "forensics"
subcategory: "shellcode"
type: "technique"
tags: ["my-notes", "personal", "shellcode", "dotnet", "tools", "dll", "forensics"]
summary: "https://github.com/icsharpcode/ILSpy"
source:
  name: "Personal notes"
origin_path: "Forensics/Tools for DLL.md"
---

https://github.com/icsharpcode/ILSpy
https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.ILSpyCmd

https://github.com/dzzie/SCDBG

> **Info** scdbg download
> Author: David ZimmerDate: 01.21.11 - 5:27am scdbg is a shellcode analysis application built around the libemu emulation library. When run it will display to the user all of the Windows API the shellcode attempts to call. What I wanted was a emulation version of sclog that I could be free to run without worry on my dekstop.  
> [http://sandsprite.com/blogs/index.php?uid=7&pid=152](http://sandsprite.com/blogs/index.php?uid=7&pid=152)  

https://github.com/guelfoweb/peframe

### run shellcode in linux

```
wine ~/Desktop/tools/forensics/scdbg_binaries/scdbg.exe -findsc /f shellcode.sc
```

### Reference

```
https://forensicskween.com/ctf/hack-the-box/redfailure/
```

---

*From your own notes: `Forensics/Tools for DLL.md`*
