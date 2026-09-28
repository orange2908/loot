---
title: "keygenme py - PicoCTF 2021"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "keygenme", "reverse-engineering", "keygenme-py", "picoctf", "adamkadaban"]
summary: "rev writeup for \"keygenme py\" from PicoCTF - techniques: keygenme, reverse-engineering, keygenme-py, picoctf, adamkadaban."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PicoCTF%202021/rev/keygenme-py/README.md"
ctf:
  name: "PicoCTF"
  year: 2021
  challenge: "keygenme py"
---

## Source

- **CTF:** PicoCTF 2021
- **Challenge:** keygenme py
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PicoCTF%202021/rev/keygenme-py/README.md>

---
* I modified the original python file to print out the key
* The important part is that they already give you most of the flag in `key_part_static1_trial`:
	```
	key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
	key_part_dynamic1_trial = "f911a486"
	key_part_static2_trial = "}"
	key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
	```

* The `check_key()` function they give checks the first part of the flag and then the second
	* It checks the second 1 character at a time with lines similar to:
		`hashlib.sha256(username_trial).hexdigest()[4]`
	* Thus, just add the characters from what they are checking to get the 2nd part of the flag

* The flag is `picoCTF{1n_7h3_|<3y_of_f911a486}`
