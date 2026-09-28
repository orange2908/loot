---
title: "XOR two images (Forensics)"
category: "forensics"
subcategory: "scripts"
type: "script"
tags: ["my-notes", "personal", "xor", "images", "forensics", "scripts"]
summary: "Personal note: XOR two images (Forensics)."
source:
  name: "Personal notes"
origin_path: "scripts/Forensics/XOR two images.md"
---

```python
from PIL import Image, ImageChops

im1 = Image.open('lemur.png')
im2 = Image.open('flag.png')

im3 = ImageChops.add(ImageChops.subtract(im2, im1), ImageChops.subtract(im1, im2))
im3.save("./result.png")
```

---

*From your own notes: `scripts/Forensics/XOR two images.md`*
