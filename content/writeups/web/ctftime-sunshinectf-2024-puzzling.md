---
title: "Puzzling - SunshineCTF 2024"
category: "web"
subcategory: "xxe"
type: "writeup"
tags: ["web", "xxe", "base64", "puzzling", "sunshinectf", "sunshinectf-2024", "2024", "ctf-writeup"]
summary: "The challenge involved uploading a custom XML file to a Sudoku web application with a restrictive XML structure that required the use of parameter entities."
source:
  name: "CTFtime writeup #39579"
  url: "https://ctftime.org/writeup/39579"
original_source: "https://humble-raptor-f30.notion.site/SunshineCTF-2024-1254c8e5237680128414c01ddd42cc09?pvs=4"
ctf:
  name: "SunshineCTF 2024"
  year: 2024
  challenge: "Puzzling"
---

## Metadata

- **CTF:** SunshineCTF 2024
- **Task:** Puzzling
- **Author team:** BeckMeister_City
- **CTFtime tags:** xxe
- **CTFtime:** <https://ctftime.org/writeup/39579>
- **Original writeup:** <https://humble-raptor-f30.notion.site/SunshineCTF-2024-1254c8e5237680128414c01ddd42cc09?pvs=4>

---
The challenge involved uploading a custom XML file to a Sudoku web application with a restrictive XML structure that required the use of parameter entities. By setting up an out-of-band (OOB) listener,I successfully tested for XXE by referencing an external entity and extracted the /etc/hostname and later the /flag.txt file. The solution involved hosting an external XML file that defined parameter entities to exfiltrate the base64-encoded flag data.
