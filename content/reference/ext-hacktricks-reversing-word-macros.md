---
title: "Word Macros (HackTricks)"
category: "rev"
subcategory: "reversing"
type: "reference"
tags: ["hacktricks", "rev", "word", "macros", "reversing", "word-macros", "junk-code", "junk"]
summary: "Macros may contain unreachable or irrelevant code intended to slow analysis."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/reversing/word-macros.md"
license: "CC BY-NC 4.0"
---

# Word Macros


## Junk Code

Macros may contain **unreachable or irrelevant code** intended to slow analysis. Identify constant conditions and trace reachable behavior before spending time reversing a branch. The example below uses an `If` condition that can never be true to conceal junk code.

![A Word macro containing an unreachable conditional branch with junk code](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(369).png)

## Macro Forms

VBA UserForms can store data in controls such as text boxes. Because forms, frames, and pages can each expose a `Controls` collection, analysts should enumerate the entire control hierarchy rather than relying only on what the form displays. The example below stores concealed data in overlapping text boxes.<sup>[[1]](#references)</sup>

During dynamic analysis, VBA's `GetObject` function can retrieve an Automation object from a file or attach to an already-running Automation server. Macros may use that object access to reach data that is not obvious in the visible document; inspect both the returned object and the UserForm control tree.<sup>[[2]](#references)</sup>

![A macro UserForm with data concealed in overlapping text boxes](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(344).png)

## References

- [1] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/reversing/word-macros.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
