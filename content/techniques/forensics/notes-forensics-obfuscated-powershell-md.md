---
title: "Obfuscated Powershell (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "obfuscated", "powershell", "forensics"]
summary: "Personal note: Obfuscated Powershell (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Obfuscated Powershell.md"
---

```powershell
PS /home/serioton/DFIR-labs/2-layer-security> cd ~/tools/forensics/invoke-deobfuscation/
PS /home/serioton/tools/forensics/invoke-deobfuscation> cd Code                                   
PS /home/serioton/tools/forensics/invoke-deobfuscation/Code> Import-Module ./Invoke-DeObfuscation.psd1
PS /home/serioton/tools/forensics/invoke-deobfuscation/Code> DeObfuscatedMain -ScriptPath0 ~/DFIR-labs/2-layer-security/
files.txt   home        mnt         notes.txt   root        stage1.ps1  stage2.ps1  
PS /home/serioton/tools/forensics/invoke-deobfuscation/Code> DeObfuscatedMain -ScriptPath0 ~/DFIR-labs/2-layer-security/stage2.ps1
```

---

*From your own notes: `Forensics/Obfuscated Powershell.md`*
