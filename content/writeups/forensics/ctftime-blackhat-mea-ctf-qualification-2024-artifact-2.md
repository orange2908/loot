---
title: "Artifact - BlackHat MEA CTF Qualification 2024"
category: "forensics"
subcategory: "windows"
type: "writeup"
tags: ["forensics", "blackhat", "qualifiers", "writeup2024", "2024", "registry", "privesc", "windows", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "ctf-writeup"]
summary: "\\- regfinfo: To gather metadata about the registry hive file."
source:
  name: "CTFtime writeup #39690"
  url: "https://ctftime.org/writeup/39690"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Artifact"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Artifact
- **Author team:** CY3RBULL1ES
- **CTFtime tags:** blackhat, qualifiers, challenge, writeup2024, 2024
- **CTFtime:** <https://ctftime.org/writeup/39690>

---
# Writeup  
### **Tools and Techniques Used**

\- **Tools**:  
\- `regfinfo`: To gather metadata about the registry hive file.  
\- `regfexport`: To export all keys and values from the registry hive for manual analysis.  
\- `grep`: To perform targeted searches for specific patterns (like `.exe` files) within the exported data.  
\- **Techniques**:  
\- **Manual Analysis**: Searched for executable paths and relevant registry keys commonly associated with execution tracking.  
\- **Targeted Search**: Focused on identifying registry paths where `.exe` files are stored, such as `AppCompatCache`, `ShimCache`, and `MUICache`.

\---

### **Step-by-Step Methodology**

1\. **Initial Metadata Check**:  
  
The `regfinfo` command was used to inspect the basic metadata of the registry hive file:  
  
```bash  
regfinfo execution  
```  
  
This provided details about the hive structure, such as the number of subkeys and values, and confirmed the file was ready for analysis.  
  
2\. **Export Registry Hive Data**:  
  
Using `regfexport`, the registry hive file was exported to a text file (`all_keys.txt`) for comprehensive analysis:  
  
```bash  
regfexport execution > all_keys.txt  
```  
  
3\. **Search for Executable Paths**:  
  
A targeted search was performed to locate executable files within the registry hive. Since `.exe` files are often stored under specific keys, such as:  
  
\- **`AppCompatCache`**: Tracks execution history for compatibility.  
\- **`ShimCache`**: Caches details of recently executed files.  
\- **`Run` Keys**: Stores programs set to run at startup.  
  
A manual analysis was conducted on `all_keys.txt` for these keys. Additionally, executables were filtered using `grep`:  
  
```bash  
grep -i ".exe" all_keys.txt  
```  


This command filtered out entries related to executables, which were manually reviewed.

I searched all the .exe files and found `DeadPotato-NET4.exe`

**Deadpotato** is a **Windows Privilege Escalation utility**, part of the well-known “Potato” family of exploits. These exploits are widely recognized for their clever methods of escalating privileges on Windows systems

![image.png](<https://prod-files-secure.s3.us-west-2.amazonaws.com/40e83586-878e-4c5c-a260-d5f93024fdd8/b228973f-7b62-41fa-973d-19f6cae5a56c/image.png>)

4\. Extracting the FILETIME  
To retrieve additional details such as timestamps, the specific key was investigated further:

The binary data associated with the timestamp was in **REG_BINARY** format, displayed as follows:

```bash  
Value: 33 \Device\HarddiskVolume2\Users\Labib\Desktop\AmcacheParser\DeadPotato-NET4.exe  
Type: binary data (REG_BINARY)  
Data size: 24  
Data:  
00000000: 8a 23 3f 9a b0 ea da 01 00 00 00 00 00 00 00 00 .#?..........   
00000010: 00 00 00 00 02 00 00 00 ..........  
```

![image.png](<https://prod-files-secure.s3.us-west-2.amazonaws.com/40e83586-878e-4c5c-a260-d5f93024fdd8/90593cc8-6734-453f-883d-3cae45fedc9c/image.png>)

The relevant 8-byte timestamp is:

`8a 23 3f 9a b0 ea da 01` 

5\. Converting the FILETIME Timestamp:  
To interpret this timestamp, we used a **Python script** to convert the binary **FILETIME** value into a human-readable format. Below is the code used for the conversion:

```python

import struct  
from datetime import datetime, timedelta

# Example binary data from the registry  
binary_data = bytes([0x8a, 0x23, 0x3f, 0x9a, 0xb0, 0xea, 0xda, 0x01])

# Convert the binary data to a 64-bit integer (FILETIME)  
filetime = struct.unpack("
